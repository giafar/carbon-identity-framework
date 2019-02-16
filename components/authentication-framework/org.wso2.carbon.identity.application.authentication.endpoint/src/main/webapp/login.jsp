<%--
  ~ Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@page import="com.google.gson.Gson" %>
<%@page import="org.wso2.carbon.identity.application.authentication.endpoint.util.AuthContextAPIClient" %>
<%@page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityCoreConstants" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityUtil" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.STATUS" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.STATUS_MSG" %>
<%@ page
        import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.CONFIGURATION_ERROR" %>
<%@ page
        import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.AUTHENTICATION_MECHANISM_NOT_CONFIGURED" %>
<%@ page
        import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.ENABLE_AUTHENTICATION_WITH_REST_API" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.Map" %>
<%@include file="localize.jsp" %>
<jsp:directive.include file="init-url.jsp"/>

<%!
    private static final String FIDO_AUTHENTICATOR = "FIDOAuthenticator";
    private static final String IWA_AUTHENTICATOR = "IwaNTLMAuthenticator";
    private static final String IS_SAAS_APP = "isSaaSApp";
    private static final String BASIC_AUTHENTICATOR = "BasicAuthenticator";
    private static final String IDENTIFIER_EXECUTOR = "IdentifierExecutor";
    private static final String OPEN_ID_AUTHENTICATOR = "OpenIDAuthenticator";
    private static final String JWT_BASIC_AUTHENTICATOR = "JWTBasicAuthenticator";
%>

    <%
        request.getSession().invalidate();
        String queryString = request.getQueryString();
        Map<String, String> idpAuthenticatorMapping = null;
        if (request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP) != null) {
            idpAuthenticatorMapping = (Map<String, String>) request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP);
        }

        String errorMessage = "authentication.failed.please.retry";
        String errorCode = "";
        if(request.getParameter(Constants.ERROR_CODE)!=null){
            errorCode = request.getParameter(Constants.ERROR_CODE) ;
        }
        String loginFailed = "false";

        if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
            loginFailed = "true";
            String error = request.getParameter(Constants.AUTH_FAILURE_MSG);
            if (error != null && !error.isEmpty()) {
                errorMessage = error;
            }
        }
    %>
    <%

        boolean hasLocalLoginOptions = false;
        boolean isBackChannelBasicAuth = false;
        List<String> localAuthenticatorNames = new ArrayList<String>();

        if (idpAuthenticatorMapping != null && idpAuthenticatorMapping.get(Constants.RESIDENT_IDP_RESERVED_NAME) != null) {
            String authList = idpAuthenticatorMapping.get(Constants.RESIDENT_IDP_RESERVED_NAME);
            if (authList != null) {
                localAuthenticatorNames = Arrays.asList(authList.split(","));
            }
        }


    %>
    <%
        boolean reCaptchaEnabled = false;
        if (request.getParameter("reCaptcha") != null && "TRUE".equalsIgnoreCase(request.getParameter("reCaptcha"))) {
            reCaptchaEnabled = true;
        }
    %>
    <%
        String inputType = request.getParameter("inputType");
        String username = null;
    
        if (isIdentifierFirstLogin(inputType)) {
            String authAPIURL = application.getInitParameter(Constants.AUTHENTICATION_REST_ENDPOINT_URL);
            if (StringUtils.isBlank(authAPIURL)) {
                authAPIURL = IdentityUtil.getServerURL("/api/identity/auth/v1.1/", true, true);
            }
            if (!authAPIURL.endsWith("/")) {
                authAPIURL += "/";
            }
            authAPIURL += "context/" + request.getParameter("sessionDataKey");
            String contextProperties = AuthContextAPIClient.getContextProperties(authAPIURL);
            Gson gson = new Gson();
            Map<String, Object> parameters = gson.fromJson(contextProperties, Map.class);
            username = (String) parameters.get("username");
        }
        
    %>
    <html>
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><%=AuthenticationEndpointUtil.i18n(resourceBundle, "wso2.identity.server")%></title>

        <link rel="icon" href="images/favicon.png" type="image/x-icon"/>
        <link href="libs/bootstrap_3.3.5/css/bootstrap.min.css" rel="stylesheet">
        <link href="css/Roboto.css" rel="stylesheet">
        <link href="css/custom-common.css" rel="stylesheet">
		<link type="text/css" rel="stylesheet" href="css/spid-sp-access-button.min.css" />
		
        <!--[if lt IE 9]>
        <script src="js/html5shiv.min.js"></script>
        <script src="js/respond.min.js"></script>
        <![endif]-->

        <%
            if (reCaptchaEnabled) {
        %>
        <script src='<%=
        (request.getParameter("reCaptchaAPI"))%>'></script>
        <%
            }
        %>

         <script>

	function checkSessionKey() {
                $.ajax({
                    type: "GET",
                    url: "/logincontext?sessionDataKey=" + getParameterByName("sessionDataKey") + "&relyingParty=" + getParameterByName("relyingParty") + "&tenantDomain=" + getParameterByName("tenantDomain"),
                    success: function (data) {
                        if (data && data.status == 'redirect' && data.redirectUrl && data.redirectUrl.length > 0) {
                            window.location.href = data.redirectUrl;
                        }
                    }
                });
            }


	function getParameterByName(name, url) {
             if (!url) {
                url = window.location.href;
             }
             name = name.replace(/[\[\]]/g, '\\$&');
             var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
             results = regex.exec(url);
             if (!results) return null;
             if (!results[2]) return "";
             return decodeURIComponent(results[2].replace(/\+/g, ' '));
         }
         </script>
    </head>

    <body onload="checkSessionKey()">

    <!-- header -->
    <header class="header header-default">
        <div class="container-fluid"><br></div>
        <div class="container-fluid">
            <div class="pull-left brand float-remove-xs text-center-xs">
                <a href="#">
                    <h1><em>Puglia DMS - Login</em></h1>
                </a>
            </div>
        </div>
    </header>

    <!-- page content -->
    <div class="container-fluid body-wrapper">

        <div class="row">
            <div class="col-md-12">

                <!-- content -->
                <div class="container col-xs-10 col-sm-6 col-md-6 col-lg-4 col-centered wr-content wr-login col-centered">
                    <div>
                        <h2 class="wr-title uppercase blue-bg padding-double white boarder-bottom-blue margin-none">
                            <%
                                if (isIdentifierFirstLogin(inputType)) {
                            %>
                            <%=AuthenticationEndpointUtil.i18n(resourceBundle, "welcome") + " " + username%>
    
                            <%
                                } else {
                            %>
                            <%=AuthenticationEndpointUtil.i18n(resourceBundle, "login")%>
                            <%
                                }
                            %>
                            
                        </h2>
                    </div>
                    <div class="boarder-all ">
                        <div class="clearfix"></div>
                        <div class="padding-double login-form">
                            <%
                                if (localAuthenticatorNames.size() > 0) {

                                    if (localAuthenticatorNames.size() > 0 && localAuthenticatorNames.contains(OPEN_ID_AUTHENTICATOR)) {
                                        hasLocalLoginOptions = true;
                            %>

                            <%@ include file="openid.jsp" %>
                            <%
                            } else if (localAuthenticatorNames.size() > 0 && localAuthenticatorNames.contains(IDENTIFIER_EXECUTOR)) {
                                hasLocalLoginOptions = true;
                            %>
                                <%@ include file="identifierauth.jsp" %>
                            <%
                            } else if (localAuthenticatorNames.size() > 0 && localAuthenticatorNames.contains(JWT_BASIC_AUTHENTICATOR) ||
                                    localAuthenticatorNames.contains(BASIC_AUTHENTICATOR)) {
                                hasLocalLoginOptions = true;
                                boolean includeBasicAuth = true;
                                if (localAuthenticatorNames.contains(JWT_BASIC_AUTHENTICATOR)) {
                                    if (Boolean.parseBoolean(application.getInitParameter(ENABLE_AUTHENTICATION_WITH_REST_API))) {
                                        isBackChannelBasicAuth = true;
                                    } else {
                                        String redirectURL = "error.do?" + STATUS + "=" + CONFIGURATION_ERROR + "&" +
                                                STATUS_MSG + "=" + AUTHENTICATION_MECHANISM_NOT_CONFIGURED;
                                        response.sendRedirect(redirectURL);
                                    }
                                } else if (localAuthenticatorNames.contains(BASIC_AUTHENTICATOR)) {
                                    isBackChannelBasicAuth = false;
                                if (TenantDataManager.isTenantListEnabled() && Boolean.parseBoolean(request.getParameter(IS_SAAS_APP))) {
                                    includeBasicAuth = false;
%>
                            <%@ include file="tenantauth.jsp" %>
<%
                            }
                                }
                            
                            if (includeBasicAuth) {
                                        %>
                                            <%@ include file="basicauth.jsp" %>
                                        <%
                                    }
                                }
                            }
                            %>

                            <%if (idpAuthenticatorMapping != null &&
                                    idpAuthenticatorMapping.get(Constants.RESIDENT_IDP_RESERVED_NAME) != null) { %>

                            <%} %>
                            <%
                                if ((hasLocalLoginOptions && localAuthenticatorNames.size() > 1) || (!hasLocalLoginOptions)
                                        || (hasLocalLoginOptions && idpAuthenticatorMapping != null && idpAuthenticatorMapping.size() > 1)) {
                            %>
                            <div class="form-group">
                                <% if (hasLocalLoginOptions) { %>
                                <%} %>
                            </div>
                            <div class="form-group">
                            <!-- SPID SAML -->
<div style="width:100%">
<form name="spid_idp_access"  id="spid_idp_access" action="#" method="post" >
        <a href="#" class="italia-it-button italia-it-button-size-l button-spid" spid-idp-button="#spid-idp-button-large-post" aria-haspopup="true" aria-expanded="false">
            <span class="italia-it-button-icon"><img src="images/spid/spid-ico-circle-bb.svg" onerror="this.src='images/spid/spid-ico-circle-bb.png'; this.onerror=null;" alt="" /></span>
            <span class="italia-it-button-text">Entra con SPID</span>
        </a>
        <div id="spid-idp-button-large-post" class="spid-idp-button spid-idp-button-tip spid-idp-button-relative">
            <ul id="spid-idp-list-large-root-post" class="spid-idp-button-menu" aria-labelledby="spid-idp">
                                <%
                                    int iconId = 0;
                                    if (idpAuthenticatorMapping != null) {
                                    for (Map.Entry<String, String> idpEntry : idpAuthenticatorMapping.entrySet()) {
                                        iconId++;
                                        if (!idpEntry.getKey().equals(Constants.RESIDENT_IDP_RESERVED_NAME)) {
                                            String idpName = idpEntry.getKey();
                                            boolean isHubIdp = false;
                                            if (idpName.endsWith(".hub")) {
                                                isHubIdp = true;
                                                idpName = idpName.substring(0, idpName.length() - 4);
                                            }
                                %>
                                				<% if (isHubIdp) { %>
                                				<!-- HUB RIMOSSO -->
                                				<%} else { %>
                                				<!-- SPID ENTRY -->
                                <!-- BOTTONE SPID -->
                                <li class="spid-idp-button-link" data-idp="<%=idpName%>">
                    					<button class="idp-button-idp-logo" name="<%=idpName%>" type="submit"><span class="spid-sr-only"><%=idpName%></span>
                    					<img class="spid-idp-button-logo" src="images/spid/spid-<%=idpName%>.svg" onerror="this.src='images/spid/spid-<%=idpName%>.png'; this.onerror=null;" alt="<%=idpName%>" /></button>
                					</li>
                                <!-- FINE BOTTONE SPID -->
                                    	<!-- FINE SPID ENTRY -->
                                <%} %>
                <li class="spid-idp-support-link" data-spidlink="info">
                    <a href="https://www.spid.gov.it">Maggiori informazioni</a>
                </li>
                <li class="spid-idp-support-link" data-spidlink="rich">
                    <a href="https://www.spid.gov.it/richiedi-spid">Non hai SPID?</a>
                </li>
                <li class="spid-idp-support-link" data-spidlink="help">
                    <a href="https://www.spid.gov.it/serve-aiuto">Serve aiuto?</a>
                </li>
            </ul>
        </div>
    </form>
    <div class="col-lg-12" style="text-align: right; margin-bottom: 20px;">
        <span>
            <a style="cursor:pointer; margin-left: 30px;margin-bottom: 20px;" target="_new" href="https://www.dms.puglia.it/assets/documents/DMS_guida_operatori.pdf"><u>Cos'è SPID?</u></a>
    </span></div>
                                	<!-- FINE SPID SAML  -->
                                <%
                                } else if (localAuthenticatorNames.size() > 0) {
                                    if (localAuthenticatorNames.contains(IWA_AUTHENTICATOR)) {
                                %>
                                <div>
                                <a onclick="javascript: handleNoDomain('<%=Encode.forJavaScriptAttribute(Encode.
                                forUriComponent(idpEntry.getKey()))%>',
                                        'IWAAuthenticator')" class="main-link" style="cursor:pointer" id="icon-<%=iconId%>">
                                    <img class="idp-image" src="images/login-icon.png" data-toggle="tooltip"
                                         data-placement="top" title="<%=AuthenticationEndpointUtil.i18n(resourceBundle,
                                                       "sign.in.with")%> IWA"/>
                                </a>
                                <label for="icon-<%=iconId%>">IWA</label>
                                </div>
                                <%
                                    }
                                    if (localAuthenticatorNames.contains(FIDO_AUTHENTICATOR)) {
                                %>
                                <div>
                                <a onclick="javascript: handleNoDomain('<%=Encode.forJavaScriptAttribute(Encode.
                                forUriComponent(idpEntry.getKey()))%>',
                                        'FIDOAuthenticator')" class="main-link" style="cursor:pointer" id="icon-<%=iconId%>">
                                    <img class="idp-image" src="images/login-icon.png" data-toggle="tooltip"
                                         data-placement="top" title="<%=AuthenticationEndpointUtil.i18n(resourceBundle,
                                                       "sign.in.with")%> FIDO"/>
                                </a>
                                <label for="icon-<%=iconId%>">FIDO</label>

                                </div>
                                <%
                                            }
                                    if (localAuthenticatorNames.contains("totp")) {
                                %>
                                <div>
                                <a onclick="javascript: handleNoDomain('<%=Encode.forJavaScriptAttribute(Encode.
                                forUriComponent(idpEntry.getKey()))%>',
                                        'totp')" class="main-link" style="cursor:pointer" id="icon-<%=iconId%>">
                                    <img class="idp-image" src="images/login-icon.png" data-toggle="tooltip"
                                         data-placement="top" title="<%=AuthenticationEndpointUtil.i18n(resourceBundle,
                                                       "sign.in.with")%> TOTP"/>
                                </a>
                                <label for="icon-<%=iconId%>">TOTP</label>

                                </div>
                                <%
                                            }
                                        }

                                    }
                                    }%>

                            </div>


                            <% } %>
                            
                            <div class="clearfix"></div>

                        </div>
                    </div>
                    <!-- /content -->

                </div>
            </div>
            <!-- /content/body -->

        </div>
    </div>

    <!-- footer -->
    <footer class="footer">
        <div class="row">
        	<div class="col-.g-1">
        	</div>
        </div>
    </footer>

    <script src="libs/jquery_1.11.3/jquery-1.11.3.js"></script>
    <script src="libs/bootstrap_3.3.5/js/bootstrap.min.js"></script>
<!-- SPID -->
<script type="text/javascript" src="js/spid-sp-access-button.min.js"></script>
<script>
$(document).ready(function(){
    var rootList = $("#spid-idp-list-large-root-post");
    var idpList = rootList.children(".spid-idp-button-link");
    var lnkList = rootList.children(".spid-idp-support-link");
    while (idpList.length) {
        rootList.append(idpList.splice(Math.floor(Math.random() * idpList.length), 1)[0]);
    }
    rootList.append(lnkList);
});
$("#spid_idp_access").submit(function (e){
	return false;
});
$("#spid_idp_access button").click(function(e){
	handleNoDomain($(this).attr("name"), 'SAMLSSOAuthenticator');
	return false;
});
</script>
<!-- FINE SPID -->
    <script>
        $(document).ready(function () {
            $('.main-link').click(function () {
                $('.main-link').next().hide();
                $(this).next().toggle('fast');
                var w = $(document).width();
                var h = $(document).height();
                $('.overlay').css("width", w + "px").css("height", h + "px").show();
            });
            $('[data-toggle="popover"]').popover();
            $('.overlay').click(function () {
                $(this).hide();
                $('.main-link').next().hide();
            });

            <%
            if(reCaptchaEnabled) {
            %>
            var error_msg = $("#error-msg");
            $("#loginForm").submit(function (e) {
                var resp = $("[name='g-recaptcha-response']")[0].value;
                if (resp.trim() == '') {
                    error_msg.text("<%=AuthenticationEndpointUtil.i18n(resourceBundle,"please.select.recaptcha")%>");
                    error_msg.show();
                    $("html, body").animate({scrollTop: error_msg.offset().top}, 'slow');
                    return false;
                }
                return true;
            });
            <%
            }
            %>
        });
        function myFunction(key, value, name) {
            var object = document.getElementById(name);
            var domain = object.value;


            if (domain != "") {
                document.location = "<%=commonauthURL%>?idp=" + key + "&authenticator=" + value +
                        "&sessionDataKey=<%=Encode.forUriComponent(request.getParameter("sessionDataKey"))%>&domain=" +
                        domain;
            } else {
                document.location = "<%=commonauthURL%>?idp=" + key + "&authenticator=" + value +
                        "&sessionDataKey=<%=Encode.forUriComponent(request.getParameter("sessionDataKey"))%>";
            }
        }

        function handleNoDomain(key, value) {
            <%
                String multiOptionURIParam = "";
                if (localAuthenticatorNames.size() > 1 || idpAuthenticatorMapping.size() > 1) {
                    multiOptionURIParam = "&multiOptionURI=" + Encode.forUriComponent(request.getRequestURI() +
                        (request.getQueryString() != null ? "?" + request.getQueryString() : ""));
                }
            %>
            document.location = "<%=commonauthURL%>?idp=" + key + "&authenticator=" + value +
                    "&sessionDataKey=<%=Encode.forUriComponent(request.getParameter("sessionDataKey"))%>" +
                    "<%=multiOptionURIParam%>";
        }

        $('#popover').popover({
            html: true,
            title: function () {
                return $("#popover-head").html();
            },
            content: function () {
                return $("#popover-content").html();
            }
        });
        window.onunload = function(){};
    </script>

    <script>
        function changeUsername (e) {
            document.getElementById("changeUserForm").submit();
        }
    </script>

    <%!
        private boolean isIdentifierFirstLogin(String inputType) {
            return "idf".equalsIgnoreCase(inputType);
        }
    %>

    </body>
    </html>
