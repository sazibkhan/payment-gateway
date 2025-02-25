package com.sslcommerz.payment_gateway.repository;

import com.sslcommerz.payment_gateway.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token,Long> {


    Optional<Token> findByToken(String token);

    @Query("""
    SELECT t FROM Token t INNER JOIN User u ON t.user.id=u.id
    WHERE t.user.id=:userId and t.logout=false 
""")
    List<Token> findAllTokenByUser(Long userId);





}

