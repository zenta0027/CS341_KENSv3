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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

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
	if(0) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *cliaddr, socklen_t *addrlen)
{
	//TODO: find socketData from list using sockfd
	if(0) //TODO: do it when cannot find socketData in list
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
	printf("bind, socketList.size() = %d\n", socketList.size());
	//TODO: check if port is already being used by another socket in the list.
	//however differet IP can use same port number.
	struct sockaddr_in *addr_in = (struct sockaddr_in *)my_addr;
	auto port = addr_in->sin_port;
	unsigned char* c = (unsigned char*)&addr_in->sin_addr;
	printf("addr bytes = ");
	for (int i = 0; i < sizeof(in_addr); i++)
	{
		printf("%02x ", *c);
		c++;
	}
	printf("\n");
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		//if (memcmp(&addr_in->sin_addr, socketList[i], addrlen) == 0 && socketList[i]->sin_port == port)
		if(socketList[i]->sin_port == port && (socketList[i]->sin_addr.s_addr == addr_in->sin_addr.s_addr || socketList[i]->sin_addr.s_addr == INADDR_ANY))
		{
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}
	for (int i = 0; i < (int)socketList.size(); i++)
	{
		if (socketList[i]->fd == sockfd && socketList[i]->sin_family == 0)
		{
			printf("bind target found\n");
			printf("sin_family was = %d\n", socketList[i]->sin_family);
			printf("sin_port was = %d\n", socketList[i]->sin_port);
			socketList[i]->sin_family = addr_in->sin_family;
			socketList[i]->sin_port = addr_in->sin_port;
			socketList[i]->sin_addr = addr_in->sin_addr;
			//void *v1 = (void*)&socketList[i]->sin_addr;
			//void *v2 = (void*)&addr_in->sin_addr;
			//memcpy((void*)socketList[i]->sin_addr, (void*)addr_in->sin_addr, sizeof(in_addr));
			//memcpy(v1, v2, sizeof(in_addr));
			//memcpy(v1, v2, addrlen);
			socketList[i]->sin_addr_len = addrlen;
			printf("sin_family is now = %d\n", socketList[i]->sin_family);
			printf("sin_port is now = %d\n", socketList[i]->sin_port);
			found = true;

			c = (unsigned char*)&socketList[i]->sin_addr;
			printf("copied addr bytes = ");
			for (int j = 0; j < sizeof(in_addr); j++)
			{
				printf("%02x ", *c);
				c++;
			}
			printf("\n");
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
			printf("find socket!\n");
			printf("sin_family is now = %d\n", socketList[i]->sin_family);
			printf("sin_port is now = %d\n", socketList[i]->sin_port);
			printf("sin_addr_len is now = %d\n", socketList[i]->sin_addr_len);
			//TODO: initialize with findiing socketData
			addr_in->sin_family = socketList[i]->sin_family;
			addr_in->sin_port = socketList[i]->sin_port;
			addr_in->sin_addr = socketList[i]->sin_addr;
			//memcpy(&addr_in->sin_addr, &socketList[i]->sin_addr, sizeof(in_addr));
			//memcpy(&addr_in->sin_addr, &socketList[i]->sin_addr, socketList[i]->sin_addr_len);
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


}