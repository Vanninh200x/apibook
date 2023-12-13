package com.example.apiBook.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotNull;
import java.util.List;

@Builder
@Data
public class CartItemRequest {
    @NotNull
    @JsonProperty(value = "cart_id")
    private Long CartId;
    @NotNull
    private List<ItemRequest> data;
}
