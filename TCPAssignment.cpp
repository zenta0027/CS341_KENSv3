/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	socketList = std::vector<SocketData*>();
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	struct TCPHeader header;
	packet->readData(34, &header, sizeof(struct TCPHeader));
	uint16_t TCP_control = header.off_control;	
	bool found = false;
	struct SocketData *socketData;

	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	uint32_t src_ip_32;
	uint32_t dest_ip_32;

	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	memcpy(&src_ip_32, src_ip, 4);
	memcpy(&dest_ip_32, dest_ip, 4);

	if(!check_tcp_checksum(header, src_ip, dest_ip))
	{
		freePacket(packet);
		return;
	}

	//printf("src_ip = %d\n", *src_ip);
	//printf("dest_ip = %d\n", *dest_ip);

	for (int i = 0; i < (int)socketList.size(); i++)
	{
		//printf("s_addr = %d\n", socketList[i]->sin_addr.s_addr);
		if(socketList[i]->sin_port == header.dst_port && (socketList[i]->sin_addr.s_addr == *dest_ip|| socketList[i]->sin_addr.s_addr == INADDR_ANY))
		{
			socketData = socketList[i];
			found = true;
			break;
		}
	}
	if(!found)
	{
		freePacket(packet);
		return;
	}
	switch (socketData->state)
	{			
	case State::SYN_SENT:

		break;
	case State::CLOSED:
		
		break;
	case State::LISTEN:
		//temporary code
		socketData->pin_port = header.src_port;
		socketData->pin_addr.s_addr = *src_ip;
		//remove this code and fill the switch case
		if(socketData->pin_port == header.src_port && socketData->pin_addr.s_addr == *src_ip)
		{
			
		}
		break;
	case State::ESTABLISHED:
		break;
	}

	if(TCP_control & 0x02) //syn
	{
		if(TCP_control & 0x10) //syn + ack
		{
			if(socketData->state == State::SYN_SENT)
			{
 				struct TCPHeader *newHeader;

 				memcpy(newHeader, &header, sizeof(TCPHeader));

				//change source port and destination port
				newHeader.src_port = header.dst_port;
				newHeader.dst_port = header.src_port;

 				newHeader.off_control = header.off_control | 0x10;
 				newHeader.off_control = header.off_control ^ 0x02; //ack only
				newHeader.checksum = 0; //TODO: calculate checksum
				add_tcp_sum(&newHeader, dest_ip_32, src_ip_32);

				Packet *newPacket = allocatePacket(packet->getSize());
				newPacket->writeData(14+12, dest_ip, 4);
				newPacket->writeData(14+16, src_ip, 4);
				newPacket->writeData(34, &newHeader, sizeof(TCPHeader));

				sendPacket("IPv4", newPacket);
				freePacket(packet);

				this->sendPacket("IPv4", newPacket);
				this->freePacket(packet);

				socketData->state = ESTABLISHED;
				returnSystemCall(socketData->socketUUID, 0);
				return;
			}

		}
		else //syn only
		{
			if(socketData->state == State::LISTEN)
			{
				//backlog not full
				if(socketData->backlog < 100) // TODO: change
				{
					struct TCPHeader newHeader;

					memcpy(&newHeader, &header, sizeof(TCPHeader));

					//change source port and destination port
					newHeader.src_port = header.dst_port;
					newHeader.dst_port = header.src_port;

	 				newHeader.off_control = header.off_control | 0x12; //syn + ack
					newHeader.checksum = 0; //TODO: calculate checksum
					add_tcp_sum(&newHeader, dest_ip_32, src_ip_32);

					Packet *newPacket = allocatePacket(packet->getSize());
					newPacket->writeData(14+12, dest_ip, 4);
					newPacket->writeData(14+16, src_ip, 4);
					newPacket->writeData(34, &newHeader, sizeof(TCPHeader));

					sendPacket("IPv4", newPacket);
					freePacket(packet);

					socketData->state = State::SYN_RECEIVED;
					return;
				}
				else //backlog full
				{
					freePacket(packet);
					return;
				}
			}
		}
	}
	else if(TCP_control & 0x10) //ack only
	{
		if(socketData->state == SYN_RECEIVED)
		{
			//TODO: ????
			freePacket(packet);
			return;
		}
	}
 	else
 	{
 		freePacket(packet);
 		return;
 	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type)
{
	int fd;
	if((fd = createFileDescriptor(pid)) == -1)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	SocketData* socketData = new SocketData;
	socketData->socketUUID = syscallUUID;
	socketData->fd = fd;
	socketData->pid = pid;
	socketData->sin_family = 0;
	socketData->sin_port = 0;
	socketData->state = State::CLOSED;
	//socketData->sin_addr = new in_addr;
	//socketData->sin_addr = NULL;
	//TODO: add socketData into list
	socketList.push_back(socketData);
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	//TODO: find socketData from list using sockfd
	bool found = false;
	for (int i = socketList.size()-1; i >= 0; i--)
	{
		if (socketList[i]->fd == sockfd)
		{
			delete socketList[i];
			socketList.erase(socketList.begin()+i);
			found = true;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	//TODO: remove socketData from list
	removeFileDescriptor(pid, sockfd);
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len)
{
	//syscall_read - don't have to implement now.
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void* buffer, size_t len)
{
	//syscall_write - don't have to implement now.
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, 
	struct sockaddr *serv_addr, socklen_t addrlen)
{
	//TODO: find socketData from list using sockfd
	if(0) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	//TODO: find socketData from list using sockfd
	struct SocketData *socketData;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd)
		{
			socketData = socketList[i];
			found = true;
			break;
		}
	}
	if(!found || socketData->state != State::CLOSED) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	socketData->state = State::LISTEN;
	socketData->backlog = backlog;
	//socketData->backlog_queue = new Queue<struct Connection*>;
	//socketData->handshake_queue = new Queue<struct SocketData*>;
	returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *clientaddr, socklen_t *addrlen)
{	
	int fd;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd) //&& socketList[i]->sin_family != 0)
		{
			if(socketList[i]->state != State::LISTEN)
			{
				returnSystemCall(syscallUUID, -1);
				return;
			}
			if((fd = createFileDescriptor(pid)) == -1)
			{
				returnSystemCall(syscallUUID, -1);
				return;
			}
			//*addrlen = sizeof(sockaddr);
			//memcpy(clientaddr, addr, *addrlen);
			returnSystemCall(syscallUUID, fd);
			return;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *my_addr, socklen_t addrlen)
{
	//TODO: find socketData from list using sockfd
	bool found = false;
	//TODO: check if port is already being used by another socket in the list.
	//however differet IP can use same port number.
	struct sockaddr_in *addr_in = (struct sockaddr_in *)my_addr;
	auto port = addr_in->sin_port;	
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if(socketList[i]->sin_port == port 
			&& (socketList[i]->sin_addr.s_addr == addr_in->sin_addr.s_addr 
				|| socketList[i]->sin_addr.s_addr == INADDR_ANY))
		{
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd && socketList[i]->sin_family == 0)
		{
			socketList[i]->sin_family = addr_in->sin_family;
			socketList[i]->sin_port = addr_in->sin_port;
			socketList[i]->sin_addr = addr_in->sin_addr;
			socketList[i]->sin_addr_len = addrlen;
			
			found = true;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}


	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
	//TODO: find socketData from list using sockfd
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	bool found = false;
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd) //&& socketList[i]->sin_family != 0)
		{
			//TODO: initialize with findiing socketData
			addr_in->sin_family = socketList[i]->sin_family;
			addr_in->sin_port = socketList[i]->sin_port;
			addr_in->sin_addr = socketList[i]->sin_addr;
			*addrlen = socketList[i]->sin_addr_len;
			found = true;
			break;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
	/*
	//TODO: find socketData from list using sockfd
	bool found = false;
	for (int i = 0; i < socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd && socketList[i]->sin_family == -1)
		{
			//TODO: initialize with findiing socketData
			struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
			addr_in->sin_family = socketList[i]->sin_family;
			addr_in->sin_port = socketList[i]->sin_port;
			addr_in->sin_addr = socketList[i]->sin_addr;
			found = true;
			break;
		}
	}
	if(!found) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	returnSystemCall(syscallUUID, 0);
	/*
	//TODO: find socketData from list using sockfd
	if(0) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	SocketData *socketData; //TODO: initialize with findiing socketData
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	addr_in->sin_family = socketData->sin_family;
	addr_in->sin_port = socketData->sin_port;
	addr_in->sin_addr = socketData->sin_addr;
	returnSystemCall(syscallUUID, 0);
	*/
	returnSystemCall(syscallUUID, -1);

}

void TCPAssignment::timerCallback(void* payload)
{

}

void TCPAssignment::add_tcp_checksum(TCPHeader *header, uint32_t src_ip, uint32_t dst_ip)
{
	header->checksum = 0;
	header->checksum = htons(~(NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t*)header, sizeof(TCPHeader))));
}

bool TCPAssignment::check_tcp_checksum(TCPHeader* header, uint32_t src_ip, uint32_t dst_ip)
{
	uint16_t checksum = header->checksum;
	TCPHeader *newHeader;
	memcpy(newHeader, header, sizeof(TCPHeader));
	newHeader->checksum = 0;
	//if(checksum == htons(~(NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t *)newHeader, sizeof(TCPHeader))))) return true;
	//return false;
	return checksum == htons(~(NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t *)newHeader, sizeof(TCPHeader))));
}


}