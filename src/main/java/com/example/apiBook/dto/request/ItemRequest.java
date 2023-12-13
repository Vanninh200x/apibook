package com.example.apiBook.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotNull;

@Builder
@Data
public class ItemRequest {
    @NotNull
    @JsonProperty("product_id")
    private Long productId;
    @NotNull
    private int quantity;
}
