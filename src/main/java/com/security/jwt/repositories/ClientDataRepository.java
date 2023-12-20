package com.security.jwt.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.security.jwt.entity.ClientData;

@Repository
public interface ClientDataRepository extends JpaRepository<ClientData, Integer>{

           ClientData findByUsername(String username);
	
}
