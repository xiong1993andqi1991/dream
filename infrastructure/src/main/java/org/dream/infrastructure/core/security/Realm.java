package org.dream.infrastructure.core.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class Realm extends AuthorizingRealm{

    @Autowired
    private SysService sysService;

    protected static final Logger logger = LoggerFactory.getLogger(Realm.class);

    /**
     * 认证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        // 获取凭证账号
        String username = (String) authenticationToken.getPrincipal();

        logger.info("AuthenticationInfo 开始认证-》:{}", username);

        SysUser sysUserByUserCode = null;
        List<SysPermission> permissionListByUserId = null;
        try {
            //通过账号查询用户信息
            sysUserByUserCode = sysService.findSysUserByUserCode(username);

            //通过账号查询用户菜单
            permissionListByUserId = sysService.findMenuListByUserId(username);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 账号为空返回null
        if (null == sysUserByUserCode) {
            return null;
        }

        // 相当于session里面存储的
        ActiveUser user = new ActiveUser();
        user.setUserid(sysUserByUserCode.getId());
        user.setUsercode(sysUserByUserCode.getUsercode());
        user.setUsername(sysUserByUserCode.getUsername());
        user.setMenus(permissionListByUserId);

        // 组装的info
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(
                user, sysUserByUserCode.getPassword(), ByteSource.Util.bytes(sysUserByUserCode.getSalt()), this.getClass().getName());

        return simpleAuthenticationInfo;
    }

    /**
     * 授权
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        // 取出身份信息
        ActiveUser user = (ActiveUser) principalCollection.getPrimaryPrincipal();

        logger.info("AuthorizationInfo 开始授权-》:{}", user.getUserid());

        List<SysPermission> permissionListByUserId = null;

        // 查询具体权限
        try {
            permissionListByUserId = sysService.findPermissionListByUserId(user.getUserid());
        } catch (Exception e) {
            e.printStackTrace();
        }

        List<String> permissions = null;

        if (!CollectionUtils.isEmpty(permissionListByUserId)) {
            permissions = new ArrayList<>();
            for (SysPermission perm : permissionListByUserId) {
                permissions.add(perm.getPercode());
            }
        }

        //查到权限数据，返回授权信息(要包括 上边的permissions)
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        //将上边查询到授权信息填充到simpleAuthorizationInfo对象中
        simpleAuthorizationInfo.addStringPermissions(permissions);

        return simpleAuthorizationInfo;
    }

    //清除缓存
    public void clearCached() {
        PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
        super.clearCache(principals);
    }
}
