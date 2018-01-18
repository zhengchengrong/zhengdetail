package com.zheng.upms.server.controller;

import com.zheng.common.base.BaseController;
import com.zheng.common.util.PropertiesFileUtil;
import com.zheng.common.util.RedisUtil;
import com.zheng.upms.client.shiro.session.UpmsSession;
import com.zheng.upms.client.shiro.session.UpmsSessionDao;
import com.zheng.upms.common.constant.UpmsResult;
import com.zheng.upms.common.constant.UpmsResultConstant;
import com.zheng.upms.dao.model.UpmsSystem;
import com.zheng.upms.dao.model.UpmsSystemExample;
import com.zheng.upms.rpc.api.UpmsSystemService;
import com.zheng.upms.rpc.api.UpmsUserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.util.UUID;

/**
 * 单点登录管理
 * Created by shuzheng on 2016/12/10.
 */
@Controller
@RequestMapping("/sso")
@Api(value = "单点登录管理", description = "单点登录管理")
public class SSOController extends BaseController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSOController.class);
    // 全局会话key
    private final static String ZHENG_UPMS_SERVER_SESSION_ID = "zheng-upms-server-session-id";
    // 全局会话key列表
    private final static String ZHENG_UPMS_SERVER_SESSION_IDS = "zheng-upms-server-session-ids";
    // code key
    private final static String ZHENG_UPMS_SERVER_CODE = "zheng-upms-server-code";

    @Autowired
    UpmsSystemService upmsSystemService;

    @Autowired
    UpmsUserService upmsUserService;

    @Autowired
    UpmsSessionDao upmsSessionDao;

    @ApiOperation(value = "认证中心首页")
    @RequestMapping(value = "/index", method = RequestMethod.GET)
    public String index(HttpServletRequest request) throws Exception {
        String appid = request.getParameter("appid");
        String backurl = request.getParameter("backurl");
        if (StringUtils.isBlank(appid)) {
            throw new RuntimeException("无效访问！");
        }
        // 判断请求认证系统是否注册
        UpmsSystemExample upmsSystemExample = new UpmsSystemExample();
        upmsSystemExample.createCriteria()
                .andNameEqualTo(appid);
        int count = upmsSystemService.countByExample(upmsSystemExample);
        if (0 == count) {
            throw new RuntimeException(String.format("未注册的系统:%s", appid));
        }
        return "redirect:/sso/login?backurl=" + URLEncoder.encode(backurl, "utf-8");
    }

    @ApiOperation(value = "登录")
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request) {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        String serverSessionId = session.getId().toString();// f9db2645-64d7-483d-81c1-1aaae391b13e 第一次进入登录页面的serverSessionId
        // 判断是否已登录，如果已登录，则回跳
        String code = RedisUtil.get(ZHENG_UPMS_SERVER_SESSION_ID + "_" + serverSessionId);// null 表示未登录
        // code校验值
        if (StringUtils.isNotBlank(code)) { // 如果code不为空，
            // 回跳
            String backurl = request.getParameter("backurl");
            String username = (String) subject.getPrincipal();
            if (StringUtils.isBlank(backurl)) {
                backurl = "/";
            } else {
                if (backurl.contains("?")) {
                    backurl += "&upms_code=" + code + "&upms_username=" + username;
                } else {
                    backurl += "?upms_code=" + code + "&upms_username=" + username;
                }
            }
            LOGGER.debug("认证中心帐号通过，带code回跳：{}", backurl);
            return "redirect:" + backurl;
        }
        return "/sso/login.jsp"; // 进行映射，会调转到jsp页面的sso下的login.jsp文件。
    }

    @ApiOperation(value = "登录")
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    @ResponseBody
    public Object login(HttpServletRequest request, HttpServletResponse response, ModelMap modelMap) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String rememberMe = request.getParameter("rememberMe");
        if (StringUtils.isBlank(username)) {
            return new UpmsResult(UpmsResultConstant.EMPTY_USERNAME, "帐号不能为空！");
        }
        if (StringUtils.isBlank(password)) {
            return new UpmsResult(UpmsResultConstant.EMPTY_PASSWORD, "密码不能为空！");
        }
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        String sessionId = session.getId().toString();// 当我进行登录的值 f9db2645-64d7-483d-81c1-1aaae391b13e
        // 判断是否已登录，如果已登录，则回跳，防止重复登录
        String hasCode = RedisUtil.get(ZHENG_UPMS_SERVER_SESSION_ID + "_" + sessionId);// 根据这个sessionId得到的code是null，所以要进行shiro认证
        // code校验值
        if (StringUtils.isBlank(hasCode)) {
            // 使用shiro认证
            UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);// 把账号密码传过去认证。
            try {
                if (BooleanUtils.toBoolean(rememberMe)) {//如果记住密码，将usernamePasswordToken设置为true
                    usernamePasswordToken.setRememberMe(true);
                } else {
                    usernamePasswordToken.setRememberMe(false);
                }
                /**
                 * login请求调用subject.login之后，shiro会将usernamePasswordToken传递给自定义realm,也就是UpmsRealm
                 * 此时UpmsRealm会先调用doGetAuthenticationInfo(AuthenticationToken authcToken )登录验证的方法，
                 * 验证通过后会接着调用 doGetAuthorizationInfo(PrincipalCollection principals)获取角色和权限的方法（授权），
                 * 最后返回视图 new UpmsResult(UpmsResultConstant.SUCCESS, backurl)。
                 * */
                subject.login(usernamePasswordToken); // 将这个对象传递过去交给shiro进行登录 ，会交给UpmsRealm对象去验证这个用户是否合法。
            } catch (UnknownAccountException e) {
                return new UpmsResult(UpmsResultConstant.INVALID_USERNAME, "帐号不存在！");
            } catch (IncorrectCredentialsException e) {
                return new UpmsResult(UpmsResultConstant.INVALID_PASSWORD, "密码错误！");
            } catch (LockedAccountException e) {
                return new UpmsResult(UpmsResultConstant.INVALID_ACCOUNT, "帐号已锁定！");
            } // 如果验证用户成功了，就会继续执行到这里了。
            // 更新session状态
            upmsSessionDao.updateStatus(sessionId, UpmsSession.OnlineStatus.on_line);//sessionId 更新用户在在线状态
            // 全局会话sessionId列表，供会话管理
            RedisUtil.lpush(ZHENG_UPMS_SERVER_SESSION_IDS, sessionId.toString());
            // 默认验证帐号密码正确，创建code
            String code = UUID.randomUUID().toString(); // 07489a99-5c95-4e54-a343-033918706834 随机生成
            // 全局会话的code 我们可以通过这个code来进行session判断 ZHENG_UPMS_SERVER_SESSION_ID + "_" + sessionId 表示 key          code表示value
            RedisUtil.set(ZHENG_UPMS_SERVER_SESSION_ID + "_" + sessionId, code, (int) subject.getSession().getTimeout() / 1000);
            // code校验值
            RedisUtil.set(ZHENG_UPMS_SERVER_CODE + "_" + code, code, (int) subject.getSession().getTimeout() / 1000);
        }
        // 回跳登录前地址
        String backurl = request.getParameter("backurl"); // ""
        if (StringUtils.isBlank(backurl)) {
            UpmsSystem upmsSystem = upmsSystemService.selectUpmsSystemByName(PropertiesFileUtil.getInstance().get("app.name")); //根据name获取UpmsSystem null
            backurl = null == upmsSystem ? "/" : upmsSystem.getBasepath(); // 如果upmsSystem是null 和backulr是"" 则 backulr 为 / ，否则就是数据库里面存的basepath路径
            return new UpmsResult(UpmsResultConstant.SUCCESS, backurl); // 返回json数据。 UpmsResult是bean对象
        } else {
            return new UpmsResult(UpmsResultConstant.SUCCESS, backurl);
        }
    }

    @ApiOperation(value = "校验code")
    @RequestMapping(value = "/code", method = RequestMethod.POST)
    @ResponseBody
    public Object code(HttpServletRequest request) {
        String codeParam = request.getParameter("code");
        String code = RedisUtil.get(ZHENG_UPMS_SERVER_CODE + "_" + codeParam);
        if (StringUtils.isBlank(codeParam) || !codeParam.equals(code)) {
            new UpmsResult(UpmsResultConstant.FAILED, "无效code");
        }
        return new UpmsResult(UpmsResultConstant.SUCCESS, code);
    }

    @ApiOperation(value = "退出登录")
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(HttpServletRequest request) {
        // shiro退出登录
        SecurityUtils.getSubject().logout();
        // 跳回原地址
        String redirectUrl = request.getHeader("Referer");
        if (null == redirectUrl) {
            redirectUrl = "/";
        }
        return "redirect:" + redirectUrl;
    }

}