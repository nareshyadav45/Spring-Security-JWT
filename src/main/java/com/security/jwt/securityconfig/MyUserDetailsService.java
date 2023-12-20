package com.security.jwt.securityconfig;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.security.jwt.entity.ClientData;
import com.security.jwt.repositories.ClientDataRepository;

@Service
public class MyUserDetailsService implements UserDetailsService{

	@Autowired
	private ClientDataRepository clientdataRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		ClientData clientData = clientdataRepository.findByUsername(username);
		if(clientData==null) {
			throw new UsernameNotFoundException("With Given Username Client Not Found");
		}
		return new User(clientData.getUsername(), clientData.getPassword(),new ArrayList<>());
	}

}
