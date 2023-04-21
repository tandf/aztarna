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
import datetime
import uuid
import json
import yaml
import copy

class ROSScanner(RobotAdapter):
    """
    ROSScanner class, an extension of BaseScanner for ROS.
    """
    def __init__(self):
        super().__init__()

        self.timeout = aiohttp.ClientTimeout(total=3)
        self.hosts = []

        self.logger = logging.getLogger(__name__)

        # information about failures
        self.failed_501s = []
        self.host_timeout_failures = []
        self.failed_connections = []
        self.get_system_state_timeout_failures = []
        self.get_system_state_failures = []
        self.host_failed_code1s = []

        self.get_bus_stats_timeout_failures = []
        self.get_bus_stats_failures = []
        self.bus_stats_failed_code1s = []

        self.get_bus_info_timeout_failures = []
        self.get_bus_info_failures = []
        self.bus_info_failed_code1s = []

    async def analyze_nodes(self, address, port):
        """
        Scan a node and gather all its data including topics, services and Communications.

        :param address: address of the ROS master
        :param port: port of the ROS master
        """
        async with aiohttp.ClientSession(loop=asyncio.get_event_loop(), timeout=self.timeout) as client:
            full_host = 'http://' + str(address) + ':' + str(port)

            # Send HTTP GET / request on port and check for error code 501
            try:
                async with client.get(full_host) as response:
                    if (response.status == 501):
                        ros_master_client = ServerProxy(full_host, loop=asyncio.get_event_loop(), client=client)
                        ros_host = ROSHost(address, port)
                        async with self.semaphore:
                            try:
                                code, msg, val = await ros_master_client.getSystemState('')
                                if code == 1:
                                    self.hosts.append(ros_host)
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
                                        self.host_failed_code1s.append((str(address), port))
                                    self.logger.critical(f'[-] Expected code 1 when getting system state but received code {code}. Terminating ({address}:{port})')

                            except asyncio.TimeoutError:
                                if self.failures:
                                    self.get_system_state_timeout_failures.append((str(address), port))
                                self.logger.error(f'[-] Timed out while attempting to get system state')
                            except Exception as e:
                                if self.failures:
                                    self.get_system_state_failures.append((str(address), port, str(e)))
                                self.logger.error(f'[-] Error getting system state: {e} ({address}:{port})')

                        # For each node found, extract transport/topic (bus) stats and connection info
                        if self.bus:
                            for host in self.hosts:
                                for node in host.nodes:
                                    await self.analyze_node_bus(node, node.address, node.port)

                    else:
                        if self.failures:
                            self.failed_501s.append((str(address), port, response.status))
                        self.logger.critical(f'[-] Expected error code 501, but received {response.status}. Terminating scan of port ({address}:{port})')

            except asyncio.TimeoutError:
                if self.failures:
                    self.host_timeout_failures.append((str(address), port))
                self.logger.error(f'[-] Timed out while attempting to connect to potential host port')
            except Exception as e:
                if self.failures:
                    self.failed_connections.append((str(address), port, str(e)))
                self.logger.error(f'[-] Error when attempting to connect to potential host port: {e} ({address}:{port})')

    async def analyze_node_bus(self, node, address, port):
        """
        For each node found, extract transport/topic (bus) stats and connection info.
        """
        async with aiohttp.ClientSession(loop=asyncio.get_event_loop(), timeout=self.timeout) as client:
            xmlrpcuri = 'http://' + str(address) + ':' + str(port)
            node_client = ServerProxy(xmlrpcuri, loop=asyncio.get_event_loop(), client=client)
            async with self.semaphore:
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
                                node.service_stats['numRequests'] = service_stats[0]
                                node.service_stats['bytesReceived'] = service_stats[1]
                                node.service_stats['bytesSent'] = service_stats[2]
                        else:
                            if self.failures:
                                self.bus_stats_failed_code1s.append(str(node))
                            self.logger.critical(f'[-] Expected code 1 when getting bus stats but received code {code}. Terminating ({address}:{port})')
                    except Exception as e:
                        node.stats_unexpected = True
                        node.publish_stats = []
                        node.subscribe_stats = []
                        node.service_stats = []
                        self.logger.warning(f'[-] Bus stats response in unexpected format: {e} ({address}:{port})')

                except asyncio.TimeoutError:
                    if self.failures:
                        self.get_bus_stats_timeout_failures.append((str(address), port))
                    self.logger.error(f'[-] Timed out while attempting to get bus stats')
                except Exception as e:
                    if self.failures:
                        self.get_bus_stats_failures.append((str(node), str(e)))
                    self.logger.error(f'[-] Error when attempting to get bus stats: {e} ({address}:{port})')

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
                                self.bus_stats_failed_code1s.append(str(node))
                            self.logger.critical(f'[-] Expected code 1 when getting bus info but received code {code}. Terminating ({address}:{port})')
                    except Exception as e:
                        node.info_unexpected = True
                        node.connections = []
                        self.logger.warning(f'[-] Bus (connection) info response in unexpected format: {e} ({address}:{port})')

                except asyncio.TimeoutError:
                    if self.failures:
                        self.get_bus_info_timeout_failures.append((str(address), port))
                    self.logger.error(f'[-] Timed out while attempting to get bus info')
                except Exception as e:
                    if self.failures:
                        self.get_bus_info_failures.append((str(node), str(e)))
                    self.logger.error(f'[-] Error when attempting to get bus info: {e} ({address}:{port})')

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
                    results.append(self.analyze_nodes(address, port))

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
                await self.analyze_nodes(str_line, port)

    def scan_pipe_main(self):
        asyncio.get_event_loop().run_until_complete(self.scan_pipe())

    def print_results(self, output_location=sys.stdout):
        """
        Print the information of a ROS system.
        """
        for host in self.hosts:
            for node in host.nodes:
                print('\nNode: ' + str(node), file=output_location)
                print('\n\t Published topics:', file=output_location)
                for topic in node.published_topics:
                    print('\t\t * ' + str(topic), file=output_location)
                print('\n\t Subscribed topics:', file=output_location)
                for topic in node.subscribed_topics:
                    print('\t\t * ' + str(topic), file=output_location)
                print('\n\t Services:', file=output_location)
                for service in node.services:
                    print('\t\t * ' + str(service), file=output_location)

            print('\nCommunications: ', file=output_location)
            for i in range(len(host.communications)):
                comm = host.communications[i]
                print('\n\t Communication ' + str(i) + ':', file=output_location)
                print('\t\t - Publishers:', file=output_location)
                for node in comm.publishers:
                    print('\t\t\t' + str(node), file=output_location)
                print('\t\t - Topic: ' + str(comm.topic), file=output_location)
                print('\t\t - Subscribers:', file=output_location)
                for node in comm.subscribers:
                    print('\t\t\t' + str(node), file=output_location)
            print('\n\n', file=output_location)

            if self.bus is True:
                print('Node transport/topic (bus) statistics and connection information:', file=output_location)
                for node in host.nodes:
                    print('\n\tNode: ' + str(node), file=output_location)
                    if (not (node.stats_unexpected)):
                        print('\n\t\t Publish statistics:', file=output_location)
                        for entry in node.publish_stats:
                            print('\n\t\t\t * Topic name: ' + str(entry['topicName']), file=output_location)
                            print('\t\t\t   Message data sent: ' + str(entry['messageDataSent']), file=output_location)
                            print('\t\t\t   Pub connection data: ', file=output_location)
                            if (entry['pubConnectionData']):
                                print('\t\t\t\t Connection ID: ' + str(entry['pubConnectionData']['connectionId']), file=output_location)
                                print('\t\t\t\t Bytes sent: ' + str(entry['pubConnectionData']['bytesSent']), file=output_location)
                                print('\t\t\t\t Num sent: ' + str(entry['pubConnectionData']['numSent']), file=output_location)
                                print('\t\t\t\t Connected: ' + str(entry['pubConnectionData']['connected']), file=output_location)
                        print('\n\t\t Subscribe statistics:', file=output_location)
                        for entry in node.subscribe_stats:
                            print('\n\t\t\t * Topic name: ' + str(entry['topicName']), file=output_location)
                            print('\t\t\t   Sub connection data: ', file=output_location)
                            if (entry['subConnectionData']):
                                print('\t\t\t\t Connection ID: ' + str(entry['subConnectionData']['connectionId']), file=output_location)
                                print('\t\t\t\t Bytes received: ' + str(entry['subConnectionData']['bytesReceived']), file=output_location)
                                print('\t\t\t\t Num received: ' + str(entry['subConnectionData']['numReceived']), file=output_location)
                                print('\t\t\t\t Drop estimate: ' + str(entry['subConnectionData']['dropEstimate']), file=output_location)
                                print('\t\t\t\t Connected: ' + str(entry['subConnectionData']['connected']), file=output_location)
                        print('\n\t\t Service statistics:', file=output_location)
                        if node.service_stats:
                            print('\t\t\t * Num requests' + str(node.service_stats['numRequests']), file=output_location)
                            print('\t\t\t   Bytes received' + str(node.service_stats['bytesReceived']), file=output_location)
                            print('\t\t\t   Bytes sent' + str(node.service_stats['bytesSent']), file=output_location)
                    else:
                        print("\n\t\t Statistics don't match ROS API format", file=output_location)
                        print('\t\t\t Response from node: ' + str(node.get_bus_stats_response), file=output_location)
                    if (not (node.info_unexpected)):
                        print('\n\t\t Connection information:', file=output_location)
                        for i in range(1, len(node.connections)+1):
                            print('\n\t\t\t * Connection ID: ' + str(node.connections[i-1][f'connectionId{i}']), file=output_location)
                            print('\t\t\t   Destination ID: ' + str(node.connections[i-1][f'destinationId{i}']), file=output_location)
                            print('\t\t\t   Direction: ' + str(node.connections[i-1][f'direction{i}']), file=output_location)
                            print('\t\t\t   Transport: ' + str(node.connections[i-1][f'transport{i}']), file=output_location)
                            print('\t\t\t   Topic: ' + str(node.connections[i-1][f'topic{i}']), file=output_location)
                            print('\t\t\t   Connected: ' + str(node.connections[i-1][f'connected{i}']), file=output_location)
                    else:
                        print("\n\t\t Connection information does't match ROS API format", file=output_location)
                        print('\t\t\t Response from node: ' + str(node.get_bus_info_response), file=output_location)
                print('\n\n', file=output_location)

        if self.failures is True:
            print('\nFailures:', file=output_location)
            if self.failed_501s:
                print('\n\tCode returned not 501; Num: ' + str(len(self.failed_501s)), file=output_location)
                for failure in self.failed_501s:
                    print(f'\t\t - {failure[0]}:{failure[1]}: returned {failure[2]}', file=output_location)
            if self.host_timeout_failures:
                print('\n\tTimed out while attempting to connect to host; Num: ' + str(len(self.host_timeout_failures)), file=output_location)
                for failure in self.host_timeout_failures:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)
            if self.failed_connections:
                print('\n\tConnection failed; Num: ' + str(len(self.failed_connections)), file=output_location)
                for failure in self.failed_connections:
                    print(f'\t\t - {failure[0]}:{failure[1]}: {failure[2]}', file=output_location)
            if self.get_system_state_timeout_failures:
                print('\n\tgetSystemState timeout; Num: ' + str(len(self.get_system_state_timeout_failures)), file=output_location)
                for failure in self.get_system_state_timeout_failures:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)
            if self.get_system_state_failures:
                print('\n\tgetSystemState failure; Num: ' + str(len(self.get_system_state_failures)), file=output_location)
                for failure in self.get_system_state_failures:
                    print(f'\t\t - {failure[0]}:{failure[1]}: {failure[2]}', file=output_location)
            if self.host_failed_code1s:
                print('\n\tgetSystemState code returned not 1; Num: ' + str(len(self.host_failed_code1s)), file=output_location)
                for failure in self.host_failed_code1s:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)

            if self.get_bus_stats_timeout_failures:
                print('\n\tgetBusStats timeout; Num: ' + str(len(self.get_bus_stats_timeout_failures)), file=output_location)
                for failure in self.get_bus_stats_timeout_failures:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)
            if self.get_bus_stats_failures:
                print('\n\tgetBusStats failure; Num: ' + str(len(self.get_bus_stats_failures)), file=output_location)
                for failure in self.get_bus_stats_failures:
                    print(f'\t\t - Node: {failure[0]}: {failure[1]}', file=output_location)
            if self.bus_stats_failed_code1s:
                print('\n\tgetBusStats code returned not 1; Num: ' + str(len(self.bus_stats_failed_code1s)), file=output_location)
                for failure in self.bus_stats_failed_code1s:
                    print(f'\t\t - Node: {failure}', file=output_location)
            if self.get_bus_info_timeout_failures:
                print('\n\tgetBusInfo timeout; Num: ' + str(len(self.get_bus_info_timeout_failures)), file=output_location)
                for failure in self.get_bus_info_timeout_failures:
                    print(f'\t\t - {failure[0]}:{failure[1]}', file=output_location)
            if self.get_bus_info_failures:
                print('\n\tgetBusInfo failure; Num: ' + str(len(self.get_bus_info_failures)), file=output_location)
                for failure in self.get_bus_info_failures:
                    print(f'\t\t - Node: {failure[0]}: {failure[1]}', file=output_location)
            if self.bus_info_failed_code1s:
                print('\n\tgetBusInfo code returned not 1; Num: ' + str(len(self.bus_info_failed_code1s)), file=output_location)
                for failure in self.bus_info_failed_code1s:
                    print(f'\t\t - Node: {failure}', file=output_location)
            print('\n\n', file=output_location)

    def save_to_file(self, format):
        """
        Save ROS system information, including console output, to a new file with unique filename.
        """
        datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')
        uuid4 = uuid.uuid4().hex
        if (('output' in format) or ('all' in format)):
            with open(f'{datetime_now}_{uuid4}.log', 'x') as file:
                self.print_results(file)
        if (('json' in format ) or ('JSON' in format) or ('yaml' in format) or ('YAML' in format) or ('all' in format)):
            save_dict = {
                'nodes': {},
                'failures': {
                    'failed_501s': self.failed_501s,
                    'host_timeout_failures': self.host_timeout_failures,
                    'failed_connections': self.failed_connections,
                    'get_system_state_timeout_failures': self.get_system_state_timeout_failures,
                    'get_system_state_failures': self.get_system_state_failures,
                    'host_failed_code1s': self.host_failed_code1s,
                    'get_bus_stats_timeout_failures': self.get_bus_stats_timeout_failures,
                    'get_bus_stats_failures': self.get_bus_stats_failures,
                    'bus_stats_failed_code1s': self.bus_stats_failed_code1s,
                    'get_bus_info_timeout_failures': self.get_bus_info_timeout_failures,
                    'get_bus_info_failures': self.get_bus_info_failures,
                    'bus_info_failed_code1s': self.bus_info_failed_code1s
                }
            }
            for host in self.hosts:
                for node in host.nodes:
                    node_dict = copy.deepcopy(node.__dict__)
                    node_dict['published_topics'] = [str(topic) for topic in node_dict['published_topics']]
                    node_dict['subscribed_topics'] = [str(topic) for topic in node_dict['subscribed_topics']]
                    node_dict['services'] = [str(service) for service in node_dict['services']]
                    save_dict['nodes'][node.name] = node_dict

            if (('json' in format) or ('JSON' in format) or ('all' in format)):
                with open(f'{datetime_now}_{uuid4}.json', 'x') as file:
                    json.dump(save_dict, file, indent=4)
            if (('yaml' in format) or ('YAML' in format) or ('all' in format)):
                with open(f'{datetime_now}_{uuid4}.yaml', 'x') as file:
                    file.write(yaml.dump(save_dict))

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

        with open(out_file, 'w') as file:
            file.writelines(lines)
