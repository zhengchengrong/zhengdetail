package com.zheng.upms.client.shiro.realm;

import com.zheng.common.util.MD5Util;
import com.zheng.common.util.PropertiesFileUtil;
import com.zheng.upms.dao.model.UpmsPermission;
import com.zheng.upms.dao.model.UpmsRole;
import com.zheng.upms.dao.model.UpmsUser;
import com.zheng.upms.rpc.api.UpmsApiService;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 用户认证和授权
 * Created by shuzheng on 2017/1/20.
 */
public class UpmsRealm extends AuthorizingRealm {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpmsRealm.class);

    @Autowired
    private UpmsApiService upmsApiService;

    /**
     * 授权：验证权限时调用      * doGetAuthorizationInfo什么时候会 http://blog.csdn.net/u014082617/article/details/50949386
     * http://blog.csdn.net/qq_33556185/article/details/51579680
     *@RequiresRoles("admin") ：在方法上加注解的时候；
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) principalCollection.getPrimaryPrincipal();
        UpmsUser upmsUser = upmsApiService.selectUpmsUserByUsername(username);

        // 当前用户所有角色
        List<UpmsRole> upmsRoles = upmsApiService.selectUpmsRoleByUpmsUserId(upmsUser.getUserId());
        Set<String> roles = new HashSet<>();
        for (UpmsRole upmsRole : upmsRoles) {
            if (StringUtils.isNotBlank(upmsRole.getName())) {
                roles.add(upmsRole.getName());
            }
        }

        // 当前用户所有权限
        List<UpmsPermission> upmsPermissions = upmsApiService.selectUpmsPermissionByUpmsUserId(upmsUser.getUserId());
        Set<String> permissions = new HashSet<>();
        for (UpmsPermission upmsPermission : upmsPermissions) {
            if (StringUtils.isNotBlank(upmsPermission.getPermissionValue())) {
                permissions.add(upmsPermission.getPermissionValue());
            }
        }

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permissions); // 加入所有权限
        simpleAuthorizationInfo.setRoles(roles); // 加入所有角色
        return simpleAuthorizationInfo;
    }

    /**
     * 认证：登录时调用
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username = (String) authenticationToken.getPrincipal(); // admin 获取用户名和密码
        String password = new String((char[]) authenticationToken.getCredentials());//123456
        // client无密认证
        String upmsType = PropertiesFileUtil.getInstance("zheng-upms-client").get("zheng.upms.type");
        if ("client".equals(upmsType)) {
            return new SimpleAuthenticationInfo(username, password, getName());
        }

        // 查询用户信息
        UpmsUser upmsUser = upmsApiService.selectUpmsUserByUsername(username);  // 根据用户名查询用户的信息

        if (null == upmsUser) { // 如果这个用户为空，抛出异常
            throw new UnknownAccountException(); // 错误的帐号
        }
        if (!upmsUser.getPassword().equals(MD5Util.md5(password + upmsUser.getSalt()))) { //  //如果密码错误  抛出密码错误的异常
            throw new IncorrectCredentialsException(); // 密码错误异常
        }
        if (upmsUser.getLocked() == 1) {
            throw new LockedAccountException(); // 锁定的帐号异常
        }
        //如果身份认证验证成功，返回一个AuthenticationInfo实现；
        return new SimpleAuthenticationInfo(username, password, getName());
    }

}
