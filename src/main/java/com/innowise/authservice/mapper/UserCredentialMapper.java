package com.innowise.authservice.mapper;

import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;
import com.innowise.authservice.model.entity.UserCredential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserCredentialMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "active", constant = "true")
    @Mapping(target = "refreshTokens", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    UserCredential toEntity(RegistrationRequest request);

    @Mapping(target = "isActive", source = "active")
    UserResponse toResponse(UserCredential entity);
}