#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ROS Scanner module.

:author Alias Robotics SL (https://aliasrobotics.com)
"""
import asyncio
import aiohttp
import logging
import re
from aiohttp_xmlrpc.client import ServerProxy
from aztarna.ros.commons import CommunicationROS
from aztarna.commons import RobotAdapter
from aztarna.ros.helpers import HelpersROS
from aztarna.ros.ros.helpers import Node, Topic, Service
from aztarna.ros.ros.helpers import ROSHost
import sys
from ipaddress import IPv4Address
import nmap
import random
import datetime
import uuid
import json
import yaml
import pickle
import copy
import os

class ROSScanner(RobotAdapter):
    """
    ROSScanner class, an extension of BaseScanner for ROS.
    """
    def __init__(self):
        super().__init__()

        self.timeout = aiohttp.ClientTimeout(total=3)
        self.hosts = []

        self.logger = logging.getLogger(__name__)

        self.failure_info = {
            'responses_from_high_numbered_port': [],
            'failed_501s': [],
            'host_timeout_failures': [],
            'failed_connections': [],

            'get_system_state_timeouts': [],
            'get_system_state_failures': [],
            'host_failed_code1s': [],

            'get_bus_stats_timeouts': [],
            'get_bus_stats_failures': [],
            'bus_stats_failed_code1s': [],

            'get_bus_info_timeouts': [],
            'get_bus_info_failures': [],
            'bus_info_failed_code1s': [],

            'get_param_names_timeouts': [],
            'get_param_names_failures': [],
            'param_names_failed_code1s': [],
        }

        self.critical_failures = {
            'analyze_nodes_failures': [],
            'analyze_node_bus_failures': [],
            'extract_parameters_failures': [],
            'print_results_failures': [],
            'save_to_file_failures': [],
        }

    async def check_high_numbered_ports(self, address, port):
        """
        Perform a TCP SYN scan on a high-numbered, normally-closed port to check if address may respond to any port.
        """
        if not self.check:
            return (1, {})
        else:
            high_numbered_ports = [58243]
            for i in range(self.check-1):
                random_high_numbered_port = random.randint(49152, 65535)
                while ((random_high_numbered_port in [49160, 64738]) or (random_high_numbered_port in high_numbered_ports)):
                    random_high_numbered_port = random.randint(49152, 65535)
                high_numbered_ports.append(random_high_numbered_port)
            may_respond_to_any = True
            port_states = {}
            timeout = False
            nm = nmap.PortScanner()
            for high_numbered_port in high_numbered_ports:
                try:
                    nm.scan(str(address), str(high_numbered_port), timeout=0.1)
                    state = nm[str(address)]['tcp'][high_numbered_port]['state']
                    if (state != 'open'):
                        may_respond_to_any = False
                    port_states[high_numbered_port] = state
                except nmap.PortScannerTimeout:
                    may_respond_to_any = False
                    port_states[high_numbered_port] = 'timeout'
                    timeout = True
            if timeout:
                os.system('reset')
            if not may_respond_to_any:
                return (1, port_states)
            else:
                if self.failures:
                    self.failure_info['responses_from_high_numbered_ports'].append((str(address), port, list(port_states.keys())))
                self.logger.error(f'[-] Received responses from high-numbered normally-closed ports: {list(port_states.keys())}; may respond to any port ({address}:{port})')
                return (0, port_states)

    async def check_error_code(self, full_host, client, address, port):
        """
        Send an HTTP GET / request to the specified port and check for error code 501.
        """
        try:
            async with client.get(full_host) as response:
                if (response.status == 501):
                    return 1
                else:
                    if self.failures:
                        self.failure_info['failed_501s'].append((str(address), port, response.status))
                    self.logger.error(f'[-] Expected error code 501, but received {response.status}. Terminating scan of port ({address}:{port})')
                    return 0
        except asyncio.TimeoutError:
            if self.failures:
                self.failure_info['host_timeout_failures'].append((str(address), port))
            self.logger.error(f'[-] Timed out while attempting to connect to potential host port ({address}:{port})')
            return 0
        except Exception as e:
            if self.failures:
                self.failure_info['failed_connections'].append((str(address), port, str(e)))
            self.logger.error(f'[-] Error when attempting to connect to potential host port: {e} ({address}:{port})')
            return 0

    async def catch_analyze_nodes(self, address, port):
        try:
            await self.analyze_nodes(address, port)
        except Exception as e:
            datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')
            uuid4 = uuid.uuid4().hex
            self.critical_failures['analyze_nodes_failures'].append({'address': str(address), 'port': port, 'exception': str(e), 'datetime': datetime_now, 'uuid': str(uuid4)})
            self.logger.critical(f'[!] Critical: analyze_nodes failure: {e} ({address}:{port})')
            if self.handle:
                self.catch_save_to_file(self.save_format if 'none' not in self.save_format else ['all'], file_name=f'critical-analyze_nodes_failure_{datetime_now}_{uuid4}')
            else:
                raise e

    async def analyze_nodes(self, address, port):
        """
        Scan a node and gather all its data including topics, services and Communications.

        :param address: address of the ROS master
        :param port: port of the ROS master
        """
        async with aiohttp.ClientSession(loop=asyncio.get_event_loop(), timeout=self.timeout) as client:
            full_host = 'http://' + str(address) + ':' + str(port)

            # Perform a TCP SYN scan on high-numbered, normally-closed port(s) to check if address may repsond to any port.
            high_numbered_ports_result = await self.check_high_numbered_ports(address, port)
            if high_numbered_ports_result[0] == 1:
                # Try HTTP GET / request on port and check for error code 501
                if await self.check_error_code(full_host, client, address, port) == 1:

                    ros_master_client = ServerProxy(full_host, loop=asyncio.get_event_loop(), client=client)
                    ros_host = ROSHost(address, port)
                    ros_host.high_numbered_port_states = high_numbered_ports_result[1]
                    async with self.semaphore:
                        try:
                            response = await ros_master_client.getSystemState('')
                            self.hosts.append(ros_host)
                            ros_host.get_system_state_response = response
                            try:
                                code, msg, val = response
                                if code == 1:
                                    if self.extended:
                                        publishers_array = val[0]
                                        subscribers_array = val[1]
                                        services_array = val[2]
                                        found_topics = await self.analyze_topic_types(ros_master_client)  # In order to analyze the nodes topics are needed

                                        self.extract_nodes(publishers_array, found_topics, 'pub', ros_host)
                                        self.extract_nodes(subscribers_array, found_topics, 'sub', ros_host)
                                        self.extract_services(services_array, ros_host)

                                        for topic_name, topic_type in found_topics.items():  # key, value
                                            current_topic = Topic(topic_name, topic_type)
                                            comm = CommunicationROS(current_topic)
                                            for node in ros_host.nodes:
                                                if next((x for x in node.published_topics if x.name == current_topic.name), None) is not None:
                                                    comm.publishers.append(node)
                                                if next((x for x in node.subscribed_topics if x.name == current_topic.name), None) is not None:
                                                    comm.subscribers.append(node)
                                            ros_host.communications.append(comm)
                                        await self.set_xmlrpcuri_node(ros_master_client, ros_host)
                                    await client.close()
                                    self.logger.warning('[+] ROS Host found at {}:{}'.format(ros_host.address, ros_host.port))
                                else:
                                    if self.failures:
                                        self.failure_info['host_failed_code1s'].append((str(address), port))
                                    self.logger.error(f'[-] Expected code 1 when getting system state but received code {code}. Terminating ({address}:{port})')
                            except Exception as e:
                                ros_host.system_state_response_unexpected = True
                                self.logger.error(f'[-] System state response in unexpected format: {e}. Terminating ({address}:{port})')

                        except asyncio.TimeoutError:
                            if self.failures:
                                self.failure_info['get_system_state_timeouts'].append((str(address), port))
                            self.logger.error(f'[-] Timed out while attempting to get system state ({address}:{port})')
                        except Exception as e:
                            if self.failures:
                                self.failure_info['get_system_state_failures'].append((str(address), port, str(e)))
                            self.logger.error(f'[-] Error getting system state: {e} ({address}:{port})')

                    # For each node found, extract transport/topic (bus) stats and connection info
                    if self.bus:
                        for node in ros_host.nodes:
                            if await self.catch_analyze_node_bus(node, node.address, node.port) != 1:
                                    await self.catch_analyze_node_bus(node, address, node.port)

                    # Extract information about parameter names stored on the server
                    if self.parameters:
                        await self.catch_extract_parameters(ros_host, address, port)


        if (self.when == 'every'):
            if self.out_file:
                self.write_to_file(self.out_file)
            else:
                if ('none' not in self.save_format):
                    self.catch_save_to_file(self.save_format, address_port=f'{address}:{port}')
                elif self.extended:
                    self.catch_print_results(address_port=f'{address}:{port}')

            self.hosts.clear()
            for key in self.failure_info.keys():
                self.failure_info[key].clear()

    async def catch_analyze_node_bus(self, node, address, port):
        try:
            return await self.analyze_node_bus(node, address, port)
        except Exception as e:
            datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')
            uuid4 = uuid.uuid4().hex
            self.critical_failures['analyze_node_bus_failures'].append({'node': str(node), 'address': str(address), 'port': port, 'exception': str(e), 'datetime': datetime_now, 'uuid': str(uuid4)})
            self.logger.critical(f'[!] Critical: analyze_node_bus failure: {e} ({address}:{port})')
            if self.handle:
                self.catch_save_to_file(self.save_format if 'none' not in self.save_format else ['all'], file_name=f'critical-analyze_node_bus_failure_{datetime_now}_{uuid4}')
                return 0
            else:
                raise e

    async def analyze_node_bus(self, node, address, port):
        """
        For each node found, extract transport/topic (bus) stats and connection info.
        """
        async with aiohttp.ClientSession(loop=asyncio.get_event_loop(), timeout=self.timeout) as client:
            xmlrpcuri = 'http://' + str(address) + ':' + str(port)
            node_client = ServerProxy(xmlrpcuri, loop=asyncio.get_event_loop(), client=client)
            async with self.semaphore:
                cant_connect = False
                try:
                    response = await node_client.getBusStats('')
                    node.get_bus_stats_response = response
                    try:
                        code, msg, stats = response
                        if code == 1:
                            publish_stats, subscribe_stats, service_stats = stats
                            for entry in publish_stats:
                                publish_stats_entry = {}
                                publish_stats_entry['topicName'] = entry[0]
                                publish_stats_entry['messageDataSent'] = entry[1]
                                publish_stats_entry['pubConnectionData'] = {}
                                if entry[2]:
                                    publish_stats_entry['pubConnectionData']['connectionId'] =  entry[2][0][0]
                                    publish_stats_entry['pubConnectionData']['bytesSent'] = entry[2][0][1]
                                    publish_stats_entry['pubConnectionData']['numSent'] = entry[2][0][2]
                                    publish_stats_entry['pubConnectionData']['connected'] = entry[2][0][3]
                                node.publish_stats.append(publish_stats_entry)
                            for entry in subscribe_stats:
                                subscribe_stats_entry = {}
                                subscribe_stats_entry['topicName'] = entry[0]
                                subscribe_stats_entry['subConnectionData'] = {}
                                if entry[1]:
                                    subscribe_stats_entry['subConnectionData']['connectionId'] = entry[1][0][0]
                                    subscribe_stats_entry['subConnectionData']['bytesReceived'] = entry[1][0][1]
                                    subscribe_stats_entry['subConnectionData']['numReceived'] = entry[1][0][2]
                                    subscribe_stats_entry['subConnectionData']['dropEstimate'] = entry[1][0][3]
                                    subscribe_stats_entry['subConnectionData']['connected'] = entry[1][0][4]
                                node.subscribe_stats.append(subscribe_stats_entry)
                            if service_stats:
                                try:
                                    node.service_stats.clear()
                                    node.service_stats['numRequests'] = service_stats[0]
                                    node.service_stats['bytesReceived'] = service_stats[1]
                                    node.service_stats['bytesSent'] = service_stats[2]
                                except Exception as e:
                                    self.logger.warning(f'[-] Service stats in unexpected format (or is now implemented): {e} ({address}:{port})')
                        else:
                            if self.failures:
                                self.failure_info['bus_stats_failed_code1s'].append(str(node))
                            self.logger.warning(f'[-] Expected code 1 when getting bus stats but received code {code}. Terminating ({address}:{port})')
                    except Exception as e:
                        node.stats_unexpected = True
                        node.publish_stats.clear()
                        node.subscribe_stats.clear()
                        node.service_stats.clear()
                        self.logger.warning(f'[-] Bus stats response in unexpected format: {e} ({address}:{port})')

                except asyncio.TimeoutError:
                    if self.failures:
                        self.failure_info['get_bus_stats_timeouts'].append((str(node), str(address), port))
                    self.logger.error(f'[-] Timed out while attempting to get bus stats ({address}:{port})')
                    cant_connect = True
                except Exception as e:
                    if self.failures:
                        self.failure_info['get_bus_stats_failures'].append((str(node), str(address), port, str(e)))
                    self.logger.error(f'[-] Error when attempting to get bus stats: {e} ({address}:{port})')
                    cant_connect = True

                try:
                    response = await node_client.getBusInfo('')
                    node.get_bus_info_response = response
                    try:
                        code, msg, info = response
                        if code == 1:
                            for i, entry in enumerate(info, start=1):
                                connection_entry = {}
                                connection_entry[f'connectionId{i}'] = entry[0]
                                connection_entry[f'destinationId{i}'] = entry[1]
                                connection_entry[f'direction{i}'] = entry[2]
                                connection_entry[f'transport{i}'] = entry[3]
                                connection_entry[f'topic{i}'] = entry[4]
                                connection_entry[f'connected{i}'] = entry[5]
                                node.connections.append(connection_entry)
                        else:
                            if self.failures:
                                self.failure_info['bus_info_failed_code1s'].append(str(node))
                            self.logger.warning(f'[-] Expected code 1 when getting bus info but received code {code}. Terminating ({address}:{port})')
                    except Exception as e:
                        node.info_unexpected = True
                        node.connections.clear()
                        self.logger.warning(f'[-] Bus (connection) info response in unexpected format: {e} ({address}:{port})')

                except asyncio.TimeoutError:
                    if self.failures:
                        self.failure_info['get_bus_info_timeouts'].append((str(node), str(address), port))
                    self.logger.error(f'[-] Timed out while attempting to get bus info ({address}:{port})')
                    cant_connect = True
                except Exception as e:
                    if self.failures:
                        self.failure_info['get_bus_info_failures'].append((str(node), str(address), port, str(e)))
                    self.logger.error(f'[-] Error when attempting to get bus info: {e} ({address}:{port})')
                    cant_connect = True

                await client.close()
                if not cant_connect:
                    return 1
                else:
                    return 0

    async def catch_extract_parameters(self, ros_host, address, port):
        try:
            await self.extract_parameters(ros_host, address, port)
        except Exception as e:
            datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')
            uuid4 = uuid.uuid4().hex
            self.critical_failures['extract_parameters_failures'].append({'address': str(address), 'port': port, 'exception': str(e), 'datetime': datetime_now, 'uuid': str(uuid4)})
            self.logger.critical(f'[!] Critical: extract_parameters failure: {e} ({address}:{port})')
            if self.handle:
                self.catch_save_to_file(self.save_format if 'none' not in self.save_format else ['all'], file_name=f'critical-extract_parameters_failure_{datetime_now}_{uuid4}')
            else:
                raise e

    async def extract_parameters(self, ros_host, address, port):
        """
        Extract information about names of parameters stored on the server.
        """
        async with aiohttp.ClientSession(loop=asyncio.get_event_loop(), timeout=self.timeout) as client:
            xmlrpcuri = 'http://' + str(address) + ':' + str(port)
            ros_client = ServerProxy(xmlrpcuri, loop=asyncio.get_event_loop(), client=client)
            async with self.semaphore:
                try:
                    response = await ros_client.getParamNames('')
                    ros_host.get_param_names_response = response
                    try:
                        code, msg, parameters = response
                        if code == 1:
                            ros_host.parameter_names = parameters
                        else:
                            if self.failures:
                                self.failure_info['param_names_failed_code1s'].append((str(address), port))
                            self.logger.warning(f'[-] Expected code 1 when getting param names but received code {code}. Terminating ({address}:{port})')
                    except Exception as e:
                        ros_host.param_response_unexpected = True
                        self.logger.warning(f'[-] Param names response in unexpected format: {e} ({address}:{port})')

                except asyncio.TimeoutError:
                    if self.failures:
                        self.failure_info['get_param_names_timeouts'].append((str(address), port))
                    self.logger.error(f'[-] Timed out while attempting to get param names ({address}:{port})')
                except Exception as e:
                    if self.failures:
                        self.failure_info['get_param_names_failures'].append((str(address), port, str(e)))
                    self.logger.error(f'[-] Error when attempting to get param names: {e} ({address}:{port})')

                await client.close()

    def extract_nodes(self, source_array, topics, pub_or_sub, host):
        """
        From all the data ROS Master returns, extract just the node info.

        :param source_array: A multiple level array containing data from the the ROS system state
        :param topics: A list of all topics found in the ROS system
        :param pub_or_sub: A boolean to separate publisher and subscriber nodes
        :param host: Current ROS host
        """
        source_lines = list(map(HelpersROS.process_line, list(filter(lambda x: (list(x)) is not None, source_array))))
        for source_line in source_lines:
            for node_name in source_line[1]:  # source_line[1] == nodes from a topic, is a list
                node = self.get_create_node(node_name, host)
                topic_name = source_line[0]
                topic_type = topics[topic_name]
                topic = Topic(topic_name, topic_type)
                if topic not in node.published_topics and pub_or_sub == 'pub':
                    node.published_topics.append(topic)
                if topic not in node.subscribed_topics and pub_or_sub == 'sub':
                    node.subscribed_topics.append(topic)

    @staticmethod
    def get_create_node(node_name, host):
        """
        Generate new :class:`aztarna.ros.helpers.Node` objects, and if they exist just return them.

        :param node_name: The name of the node to create or return
        :param host: Current ROS host
        :return: The newly created node or an existing that matches :attr:`node_name`
        """
        node_name_attrs = [o.name for o in host.nodes]
        if node_name not in node_name_attrs:
            ret_node = Node(node_name)
            host.nodes.append(ret_node)
        else:
            ret_node = next((x for x in host.nodes if x.name == node_name), None)

        return ret_node

    async def set_xmlrpcuri_node(self, ros_master_client, host):
        """
        Once all node data is collected, set the xml.

        :param ros_master_client: xml-rpc object for the ROS Master Client
        """
        for node in host.nodes:
            uri = await ros_master_client.lookupNode('', node.name)
            if uri[2] != '':
                regexp = re.compile(r'http://(?P<host>\S+):(?P<port>[0-9]{1,5})')
                uri_groups = regexp.search(uri[2])
                node.address = uri_groups.group('host')
                node.port = uri_groups.group('port')

    @staticmethod
    async def analyze_topic_types(ros_master_client):
        """
        Extract topic from ROS Master and disassemble them into topic name and topic type.

        :param ros_master_client:  xml-rpc object for the ROS Master Client
        :return: A dictionary of topics. Key is the topic name and value the topic type
        """
        topic_types = await ros_master_client.getTopicTypes('')
        topics = {}
        for topic_type_element in topic_types[2]:
            topic_name = topic_type_element[0]
            topic_type = topic_type_element[1]
            topics[topic_name] = topic_type
        return topics

    def extract_services(self, source_array, host):
        """
        Extract the services from the ROS system state.

        :param source_array: A multiple level array containing data from the the ROS system state
        :param host: Current ROS host
        """
        service_lines = list(map(HelpersROS.process_line, list(filter(lambda x: (list(x)) is not None, source_array))))
        for service_line in service_lines:
            for node_name in service_line[1]:  # source_line[1] == nodes from a topic, is a list
                node = self.get_create_node(node_name, host)
                node.services.append(Service(service_line[0]))

    async def scan_network(self):
        """
        Scan the provided network (from args) searching for ROS nodes.
        """
        try:
            results = []
            for port in self.ports:
                for address in self.host_list:
                    results.append(self.catch_analyze_nodes(address, port))

            for result in await asyncio.gather(*results):
                pass

        except ValueError as e:
            self.logger.error('Invalid address entered')
            raise e

    def scan(self):
        """
        Call to :meth:`aztarna.ros.scanner.scan_network` asynchronously
        """
        asyncio.get_event_loop().run_until_complete(self.scan_network())

    async def scan_pipe(self):
        async for line in RobotAdapter.stream_as_generator(asyncio.get_event_loop(), sys.stdin):
            str_line = (line.decode()).rstrip('\n')
            for port in self.ports:
                await self.catch_analyze_nodes(str_line, port)

    def scan_pipe_main(self):
        asyncio.get_event_loop().run_until_complete(self.scan_pipe())

    def catch_print_results(self, output_location=sys.stderr, address_port=None):
        try:
            self.print_results(output_location)
        except Exception as e:
            datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')
            uuid4 = uuid.uuid4().hex
            self.critical_failures['print_results_failures'].append({'output_location': str(output_location), 'address:port': address_port, 'exception': str(e), 'datetime': datetime_now, 'uuid': str(uuid4)})
            self.logger.critical(f'[!] Critical: print_results failure: {e} ({address_port})')
            if self.handle:
                print('\nPRINT_RESULTS FAILURE', file=output_location)
                self.catch_save_to_file(self.save_format if 'none' not in self.save_format else ['JSON', 'YAML'], file_name=f'critical-print_results_failure_{datetime_now}_{uuid4}')
            else:
                raise e

    def print_results(self, output_location):
        """
        Print the information of a ROS system.
        """
        for host in self.hosts:
            print(f'\nHost: {host.address}:{host.port}', file=output_location)
            if self.check:
                print('\n\tState(s) of checked high-numbered port(s):', file=output_location)
            for port, state in host.high_numbered_port_states.items():
                print('\t\t - ' + str(port) + ': ' + state, file=output_location)
            for node in host.nodes:
                print('\n\tNode: ' + str(node), file=output_location)
                print('\n\t\t Published topics:', file=output_location)
                for topic in node.published_topics:
                    print('\t\t\t * ' + str(topic), file=output_location)
                print('\n\t\t Subscribed topics:', file=output_location)
                for topic in node.subscribed_topics:
                    print('\t\t\t * ' + str(topic), file=output_location)
                print('\n\t\t Services:', file=output_location)
                for service in node.services:
                    print('\t\t\t * ' + str(service), file=output_location)

            print('\n\tCommunications: ', file=output_location)
            for i in range(len(host.communications)):
                comm = host.communications[i]
                print('\n\t\t Communication ' + str(i) + ':', file=output_location)
                print('\t\t\t - Publishers:', file=output_location)
                for node in comm.publishers:
                    print('\t\t\t\t' + str(node), file=output_location)
                print('\t\t\t - Topic: ' + str(comm.topic), file=output_location)
                print('\t\t\t - Subscribers:', file=output_location)
                for node in comm.subscribers:
                    print('\t\t\t\t' + str(node), file=output_location)
            print('\n\n', file=output_location)

            if self.bus:
                print('\tNode transport/topic (bus) statistics and connection information:', file=output_location)
                for node in host.nodes:
                    print('\n\t\tNode: ' + str(node), file=output_location)
                    if not node.stats_unexpected:
                        print('\n\t\t\t Publish statistics:', file=output_location)
                        for entry in node.publish_stats:
                            print('\n\t\t\t\t * Topic name: ' + str(entry['topicName']), file=output_location)
                            print('\t\t\t\t   Message data sent: ' + str(entry['messageDataSent']), file=output_location)
                            print('\t\t\t\t   Pub connection data: ', file=output_location)
                            if (entry['pubConnectionData']):
                                print('\t\t\t\t\t Connection ID: ' + str(entry['pubConnectionData']['connectionId']), file=output_location)
                                print('\t\t\t\t\t Bytes sent: ' + str(entry['pubConnectionData']['bytesSent']), file=output_location)
                                print('\t\t\t\t\t Num sent: ' + str(entry['pubConnectionData']['numSent']), file=output_location)
                                print('\t\t\t\t\t Connected: ' + str(entry['pubConnectionData']['connected']), file=output_location)
                        print('\n\t\t\t Subscribe statistics:', file=output_location)
                        for entry in node.subscribe_stats:
                            print('\n\t\t\t\t * Topic name: ' + str(entry['topicName']), file=output_location)
                            print('\t\t\t\t   Sub connection data: ', file=output_location)
                            if (entry['subConnectionData']):
                                print('\t\t\t\t\t Connection ID: ' + str(entry['subConnectionData']['connectionId']), file=output_location)
                                print('\t\t\t\t\t Bytes received: ' + str(entry['subConnectionData']['bytesReceived']), file=output_location)
                                print('\t\t\t\t\t Num received: ' + str(entry['subConnectionData']['numReceived']), file=output_location)
                                print('\t\t\t\t\t Drop estimate: ' + str(entry['subConnectionData']['dropEstimate']), file=output_location)
                                print('\t\t\t\t\t Connected: ' + str(entry['subConnectionData']['connected']), file=output_location)
                        print('\n\t\t\t Service statistics:', file=output_location)
                        if ('proposed' not in node.service_stats.keys()):
                            print('\t\t\t\t * Num requests' + str(node.service_stats['numRequests']), file=output_location)
                            print('\t\t\t\t   Bytes received' + str(node.service_stats['bytesReceived']), file=output_location)
                            print('\t\t\t\t   Bytes sent' + str(node.service_stats['bytesSent']), file=output_location)
                    else:
                        print("\n\t\t\t Statistics don't match ROS API format", file=output_location)
                        print('\t\t\t\t Response from node: ' + str(node.get_bus_stats_response), file=output_location)
                    if not node.info_unexpected:
                        print('\n\t\t\t Connection information:', file=output_location)
                        for i in range(1, len(node.connections)+1):
                            print('\n\t\t\t\t * Connection ID: ' + str(node.connections[i-1][f'connectionId{i}']), file=output_location)
                            print('\t\t\t\t   Destination ID: ' + str(node.connections[i-1][f'destinationId{i}']), file=output_location)
                            print('\t\t\t\t   Direction: ' + str(node.connections[i-1][f'direction{i}']), file=output_location)
                            print('\t\t\t\t   Transport: ' + str(node.connections[i-1][f'transport{i}']), file=output_location)
                            print('\t\t\t\t   Topic: ' + str(node.connections[i-1][f'topic{i}']), file=output_location)
                            print('\t\t\t\t   Connected: ' + str(node.connections[i-1][f'connected{i}']), file=output_location)
                    else:
                        print("\n\t\t\t Connection information does't match ROS API format", file=output_location)
                        print('\t\t\t\t Response from node: ' + str(node.get_bus_info_response), file=output_location)
                print('\n\n', file=output_location)

            if self.parameters:
                print('\tServer parameters:', file=output_location)
                if not host.param_response_unexpected:
                    for parameter in host.parameter_names:
                        print('\t\t - ' + parameter, file=output_location)
                else:
                    print("\tParameter name response doesn't match ROS API format", file=output_location)
                    print('\t\tServer response: ' + str(host.get_param_names_response), file=output_location)
                print('\n\n', file=output_location)

        if self.failures:
            print('Failures:', file=output_location)
            if self.failure_info['responses_from_high_numbered_port']:
                print('\n\tRecieved response from high-numbered normally-closed port; Num: ' + str(len(self.failure_info['responses_from_high_numbered_port'])), file=output_location)
                for failure in self.failure_info['responses_from_high_numbered_port']:
                    print(f'\t\t - {failure[0]}:{failure[1]}: response from {failure[2]}', file=output_location)
            if self.failure_info['failed_501s']:
                print('\n\tCode returned not 501; Num: ' + str(len(self.failure_info['failed_501s'])), file=output_location)
                for failure in self.failure_info['failed_501s']:
                    print(f'\t\t - {failure[0]}:{failure[1]}: returned {failure[2]}', file=output_location)
            if self.failure_info['host_timeout_failures']:
                print('\n\tTimed out while attempting to connect to host; Num: ' + str(len(self.failure_info['host_timeout_failures'])), file=output_location)
                for failure in self.failure_info['host_timeout_failures']:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)
            if self.failure_info['failed_connections']:
                print('\n\tConnection failed; Num: ' + str(len(self.failure_info['failed_connections'])), file=output_location)
                for failure in self.failure_info['failed_connections']:
                    print(f'\t\t - {failure[0]}:{failure[1]}: {failure[2]}', file=output_location)
            if self.failure_info['get_system_state_timeouts']:
                print('\n\tgetSystemState timeout; Num: ' + str(len(self.failure_info['get_system_state_timeouts'])), file=output_location)
                for failure in self.failure_info['get_system_state_timeouts']:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)
            if self.failure_info['get_system_state_failures']:
                print('\n\tgetSystemState failure; Num: ' + str(len(self.failure_info['get_system_state_failures'])), file=output_location)
                for failure in self.failure_info['get_system_state_failures']:
                    print(f'\t\t - {failure[0]}:{failure[1]}: {failure[2]}', file=output_location)
            if self.failure_info['host_failed_code1s']:
                print('\n\tgetSystemState code returned not 1; Num: ' + str(len(self.failure_info['host_failed_code1s'])), file=output_location)
                for failure in self.failure_info['host_failed_code1s']:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)

            if self.failure_info['get_bus_stats_timeouts']:
                print('\n\tgetBusStats timeout; Num: ' + str(len(self.failure_info['get_bus_stats_timeouts'])), file=output_location)
                for failure in self.failure_info['get_bus_stats_timeouts']:
                    print(f'\t\t - Node: {failure[0]} ({failure[1]}:{failure[2]})', file=output_location)
            if self.failure_info['get_bus_stats_failures']:
                print('\n\tgetBusStats failure; Num: ' + str(len(self.failure_info['get_bus_stats_failures'])), file=output_location)
                for failure in self.failure_info['get_bus_stats_failures']:
                    print(f'\t\t - Node: {failure[0]}: {failure[3]} ({failure[1]}:{failure[2]})', file=output_location)
            if self.failure_info['bus_stats_failed_code1s']:
                print('\n\tgetBusStats code returned not 1; Num: ' + str(len(self.failure_info['bus_stats_failed_code1s'])), file=output_location)
                for failure in self.failure_info['bus_stats_failed_code1s']:
                    print(f'\t\t - Node: {failure}', file=output_location)
            if self.failure_info['get_bus_info_timeouts']:
                print('\n\tgetBusInfo timeout; Num: ' + str(len(self.failure_info['get_bus_info_timeouts'])), file=output_location)
                for failure in self.failure_info['get_bus_info_timeouts']:
                    print(f'\t\t - Node: {failure[0]} ({failure[1]}:{failure[2]})', file=output_location)
            if self.failure_info['get_bus_info_failures']:
                print('\n\tgetBusInfo failure; Num: ' + str(len(self.failure_info['get_bus_info_failures'])), file=output_location)
                for failure in self.failure_info['get_bus_info_failures']:
                    print(f'\t\t - Node: {failure[0]}: {failure[3]} ({failure[1]}:{failure[2]})', file=output_location)
            if self.failure_info['bus_info_failed_code1s']:
                print('\n\tgetBusInfo code returned not 1; Num: ' + str(len(self.failure_info['bus_info_failed_code1s'])), file=output_location)
                for failure in self.failure_info['bus_info_failed_code1s']:
                    print(f'\t\t - Node: {failure}', file=output_location)
            print('\n\n', file=output_location)

    def catch_save_to_file(self, format, address_port=None):
        try:
            self.save_to_file(format, address_port=address_port)
        except Exception as e:
            datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')
            uuid4 = uuid.uuid4().hex
            self.critical_failures['save_to_file_failures'].append({'address:port': address_port, 'exception': str(e), 'datetime': datetime_now, 'uuid': str(uuid4)})
            self.logger.critical(f'[!] Critical: save_to_file failure: {e} ({address_port})')
            if self.handle:
                save_dict = {
                    'hosts': self.hosts,
                    'failure_info': self.failure_info,
                    'critical_failures': self.critical_failures,
                }
                try:
                    with open(f'critical-save_to_file_failure-1_{datetime_now}_{uuid4}.bin', 'xb') as file:
                        pickle.dump(save_dict, file)
                except Exception as e:
                    with open(f'critical-save_to_file_failure-1_{datetime_now}_{uuid4}.bin', 'a') as file:
                        file.write(f'\nERROR: {e}\n')

                    try:
                        save_dict['hosts'] = {}
                        for host in self.hosts:
                            save_dict['hosts'][f'{host.address}:{host.port}'] = {
                                'nodes': {},
                                'communications': {},
                                'services': host.services,
                                'high_numbered_port_state': host.high_numbered_port_states,
                                'parameter_names': host.parameter_names,
                                'get_param_names_response': host.get_param_names_response,
                                'param_response_unexpected': host.param_response_unexpected,
                                'get_system_state_response': host.get_system_state_response,
                                'system_state_response_unexpected': host.system_state_response_unexpected
                            }
                            for node in host.nodes:
                                node_dict = copy.deepcopy(node.__dict__)
                                node_dict['published_topics'] = [str(topic) for topic in node_dict['published_topics']]
                                node_dict['subscribed_topics'] = [str(topic) for topic in node_dict['subscribed_topics']]
                                node_dict['services'] = [str(service) for service in node_dict['services']]
                                save_dict['hosts'][f'{host.address}:{host.port}']['nodes'][node.name] = node_dict
                            for communication in host.communications:
                                communication_dict = copy.deepcopy(communication.__dict__)
                                communication_dict['publishers'] = [str(publisher) for publisher in communication_dict['publishers']]
                                communication_dict['subscribers'] = [str(subscriber) for subscriber in communication_dict['subscribers']]
                                communication_dict['topic'] = str(communication_dict['topic'])
                                save_dict['hosts'][f'{host.address}:{host.port}']['communications'][communication_dict['topic']] = communication_dict

                        with open(f'critical-save_to_file_failure-2_{datetime_now}_{uuid4}.bin', 'xb') as file:
                            pickle.dump(save_dict, file)

                    except Exception as e:
                        with open(f'critical-save_to_file_failure-2_{datetime_now}_{uuid4}.bin', 'a') as file:
                            file.write(f'\nERROR: {e}\n')

                        with open(f'critical-save_to_file_failure-3_{datetime_now}_{uuid4}.bin', 'x') as file:
                            file.write('UNABLE TO PICKLE\n')
            else:
                raise e

    def save_to_file(self, format, file_name=None, address_port=None):
        """
        Save ROS system information, including console output, to a new file with unique filename.
        """
        if (file_name == None):
            datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')
            uuid4 = uuid.uuid4().hex
            file_name = f'{datetime_now}_{uuid4}'

        if (('output' in format) or ('all' in format)):
            with open(f'{file_name}.log', 'x') as file:
                self.catch_print_results(file, address_port=address_port)
        if (('json' in format ) or ('JSON' in format) or ('yaml' in format) or ('YAML' in format) or ('all' in format)):
            save_dict = {
                'hosts': {},
                'failure_info': self.failure_info,
                'critical_failures': self.critical_failures
            }
            for host in self.hosts:
                save_dict['hosts'][f'{host.address}:{host.port}'] = {
                    'nodes': {},
                    'communications': {},
                    'services': host.services,
                    'high_numbered_port_state': host.high_numbered_port_states,
                    'parameter_names': host.parameter_names,
                    'get_param_names_response': host.get_param_names_response,
                    'param_response_unexpected': host.param_response_unexpected,
                    'get_system_state_response': host.get_system_state_response,
                    'system_state_response_unexpected': host.system_state_response_unexpected
                }
                for node in host.nodes:
                    node_dict = copy.deepcopy(node.__dict__)
                    node_dict['published_topics'] = [str(topic) for topic in node_dict['published_topics']]
                    node_dict['subscribed_topics'] = [str(topic) for topic in node_dict['subscribed_topics']]
                    node_dict['services'] = [str(service) for service in node_dict['services']]
                    save_dict['hosts'][f'{host.address}:{host.port}']['nodes'][node.name] = node_dict
                for communication in host.communications:
                    communication_dict = copy.deepcopy(communication.__dict__)
                    communication_dict['publishers'] = [str(publisher) for publisher in communication_dict['publishers']]
                    communication_dict['subscribers'] = [str(subscriber) for subscriber in communication_dict['subscribers']]
                    communication_dict['topic'] = str(communication_dict['topic'])
                    save_dict['hosts'][f'{host.address}:{host.port}']['communications'][communication_dict['topic']] = communication_dict

            save_error = False
            try:
                if (('json' in format) or ('JSON' in format) or ('all' in format)):
                    with open(f'{file_name}.json', 'x') as file:
                        json.dump(save_dict, file, indent=4)
            except Exception as e:
                save_dict['json_error'] = str(e)
                with open(f'{file_name}.json', 'a') as file:
                    file.write('\nERROR\n')
                self.logger.error(f'[-] Error when attempting to save as JSON: {e}; saving as byte stream instead (pickle)')
                save_error = True
            try:
                if (('yaml' in format) or ('YAML' in format) or ('all' in format)):
                    with open(f'{file_name}.yaml', 'x') as file:
                        file.write(yaml.dump(save_dict))
            except Exception as e:
                save_dict['yaml_error'] = str(e)
                with open(f'{file_name}.yaml', 'a') as file:
                    file.write('\nERROR\n')
                self.logger.error(f'[-] Error when attempting to save as YAML: {e}; saving as byte stream instead (pickle)')
                save_error = True
            if save_error:
                with open(f'{file_name}.bin', 'xb') as file:
                    pickle.dump(save_dict, file)

    def write_to_file(self, out_file):
        """
        Write the information of a ROS system into the provided file.

        :param out_file: The file where to write the results
        """
        lines = []
        header = 'Master Address;Master port;Node Name;Node Address;Port;Published Topics;Subscribed Topics;Services\n'
        lines.append(header)
        for host in self.hosts:
            line = '{};{};;;;;;\n'.format(host.address, host.port)
            if len(host.nodes) > 0:
                for node in host.nodes:
                    for ptopic in node.published_topics:
                        for stopic in node.subscribed_topics:
                            for service in node.services:
                                line = '{};{};{};{};{};{};{};{}\n'.format(host.address, host.port, node.name, node.address, node.port, ptopic,
                                                                   stopic, service)
            lines.append(line)

        with open(out_file, 'a') as file:
            file.writelines(lines)
