package com.example.apiBook.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "tokens")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Token {
    private String token;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
}
