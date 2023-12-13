package com.example.apiBook.helper;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ResponseObj {
    @JsonProperty("status_code")
    private int statusCode;
    private boolean success;
    private String message;
    private Object data;

}
