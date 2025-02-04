package com.yelm.jwtlogin.user.mapper;

import com.yelm.jwtlogin.user.entity.UserEntity;
import com.yelm.jwtlogin.user.vo.UserRequestVO;
import com.yelm.jwtlogin.user.vo.UserResponseVO;
import com.yelm.jwtlogin.user.vo.UserUpdateVO;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    // Signup
    boolean existsUserByUsername(String username);

    // Create
    void insertUser(UserRequestVO userRequestVO);

    // Read
//    UserResponseVO selectUserById(int id);
    UserResponseVO selectUserByUsername(String username);
//    List<UserResponseVO> selectAllUsers();


    // Update
    void updateUser(UserUpdateVO userUpdateVO);

    // Delete
    void deleteUser(String username);
}