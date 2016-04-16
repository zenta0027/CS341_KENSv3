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

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		//this->syscall_close(syscallUUID, pid, param.param1_int);
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
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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

void TCPAssignment::syscall_socket(UUID syscallUUID, int family, int type, int protocol)
{
	int fd;
	if((fd = createFileDescriptor(family)) == -1)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	SocketData *socketData;
	socketData->socketUUID = syscallUUID;
	socketData->fd = fd;
	//TODO: add socketData into list
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	//TODO: find socketData from list using sockfd
	if(0) //TODO: do it when cannot find socketData in list
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
	if(0) //TODO: do it when cannot find socketData in list
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
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
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t *addrlen)
{
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
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
