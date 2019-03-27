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

<%@page import="org.owasp.encoder.Encode"%>
<%@page import="java.util.List"%>
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
    private static final String FACEBOOK_AUTHENTICATOR = "FacebookAuthenticator";
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

        boolean hasLocalLoginOptions = false;
        boolean hasFacebookAuthenticator = false;
        boolean isBackChannelBasicAuth = false;
        List<String> localAuthenticatorNames = new ArrayList<String>();

        if (idpAuthenticatorMapping != null && idpAuthenticatorMapping.get(Constants.RESIDENT_IDP_RESERVED_NAME) != null) {
            String authList = idpAuthenticatorMapping.get(Constants.RESIDENT_IDP_RESERVED_NAME);
            if (authList != null) {
                localAuthenticatorNames = Arrays.asList(authList.split(","));
            }
        }

        if (idpAuthenticatorMapping != null && idpAuthenticatorMapping.entrySet().stream().anyMatch(p -> FACEBOOK_AUTHENTICATOR.equalsIgnoreCase(p.getValue()))) {
        	hasFacebookAuthenticator = true;
        }
        
        idpAuthenticatorMapping.entrySet().stream().forEach(es -> {
        	System.out.println(es.getKey() + " " + es.getValue());
        });
        
    	if (localAuthenticatorNames.size() > 0) {
    		if (localAuthenticatorNames.contains(OPEN_ID_AUTHENTICATOR)) {
    			hasLocalLoginOptions = true;
    		} else if (localAuthenticatorNames.contains(IDENTIFIER_EXECUTOR)) {
    			hasLocalLoginOptions = true;
    		} else if (localAuthenticatorNames.contains(JWT_BASIC_AUTHENTICATOR) || localAuthenticatorNames.contains(BASIC_AUTHENTICATOR)) {
                hasLocalLoginOptions = true;
    		}
    	}
        
        boolean reCaptchaEnabled = false;
        if (request.getParameter("reCaptcha") != null && "TRUE".equalsIgnoreCase(request.getParameter("reCaptcha"))) {
            reCaptchaEnabled = true;
        }

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
	
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- CSS -->
    <link rel="stylesheet" href="css/bootstrap-italia.min.css">
    <link rel="stylesheet" href="css/style.css">

    <!-- favicon -->
    <link rel="icon" href="favicon.ico">
		
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

    <div class="row">
        <div class="container main-box-bo white shadow-bo">
        	<!-- HEADER -->
            <div class="header-logo-login">
                <p class="logo-header text-center">
                    <img src="images/comune-napoli.png" style="margin-right:3%;">
                    <img src="images/ponmetro.png">
                </p>
            </div>
            <h2 class="u-text-h2 text-center margin-bottom-section">Accedi con le tue credenziali</h2>
            <!-- tabs -->
            <div class="scrollbar login-bo-container margin-bottom-section">
                <ul class="nav nav-tabs mb-3 justify-content-center" id="myTab3" role="tablist">
                <% if (hasLocalLoginOptions) { %>
                    <li class="nav-item">
                        <a class="nav-link tab-width active" id="tab1c-tab" data-toggle="tab" href="#tab1b" role="tab"
                            aria-controls="tab1b" aria-selected="true">Login semplice
                        </a>
                    </li>
                   	<% } %>
                    <li class="nav-item">
                        <a class="nav-link tab-width" id="tab2b-tab" data-toggle="tab" href="#tab2b" role="tab"
                            aria-controls="tab2b" aria-selected="false">SPID
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link tab-width" id="tab3b-tab" data-toggle="tab" href="#tab3b" role="tab"
                            aria-controls="tab3b" aria-selected="false">CIE
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link tab-width" id="tab4b-tab" data-toggle="tab" href="#tab4b" role="tab"
                            aria-controls="tab4b" aria-selected="false">CNS
                        </a>
                    </li>
                    <% if(hasFacebookAuthenticator) { %>
                    <li class="nav-item">
                        <a class="nav-link tab-width" id="tab5b-tab" data-toggle="tab" href="#tab5b" role="tab"
                            aria-controls="tab5b" aria-selected="false">Facebook
                        </a>
                    </li>
                   <% } %>
                </ul>
            </div>
            <div class="tab-content text-center" id="myTab3Content">
            <%if(hasLocalLoginOptions) { %>
            		<jsp:directive.include file="init-loginform-action-url.jsp"/>       
            		<!-- LOCAL AUTHENTICATION -->     		
                <div class="tab-pane p-4 fade show active" id="tab1b" role="tabpanel" aria-labelledby="tab1c-tab">
                <form action="<%=loginFormActionURL%>" method="post" id="usernamePasswordForm">
			    <%
			        if (loginFormActionURL.equals(samlssoURL) || loginFormActionURL.equals(oauth2AuthorizeURL)) {
			    %>
				    <input id="tocommonauth" name="tocommonauth" type="hidden" value="true">
			    <%
			        }
			    %>
        			<input type="hidden" name="sessionDataKey" value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>'/>			    
                    <div class="col-md-3 mx-auto">
                        <div class="form-group text-center">
                            <input type="text" class="form-control" id="username" name="username" >
                            <label for="login">Login</label>
                        </div>
                        <div class="form-group text-center">
                            <input type="password" class="form-control" id="password" name="password">
                            <label for="password">password</label>
                        </div>
                        <div class="form-group">
                            <div class="btn-example">
                                <button type="submit" class="btn btn-primary button-main" id='loginBtn'>Login</button>
                            </div>
                        </div>
                    </div>
                    </form>
                </div>
                <% } %>
                <!-- SPID -->
                <div class="tab-pane p-4 fade" id="tab2b" role="tabpanel" aria-labelledby="tab2b-tab">
                    <div class="col-md-3 mx-auto">
                        <div class="dropdown">
                            <button class="btn btn-primary button-main btn-dropdown dropdown-toggle" type="button"
                                id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true"
                                aria-expanded="false">
                                <span>
                                    <img width="30px" src="images/icons/spid-ico-circle-bb.png">
                                </span>
                                <span>SPID</span>
                            </button>
                            <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">
                                <div class="link-list-wrapper">
                                    <ul class="link-list">
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-sielteid.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-spiditalia.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-arubaid.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-posteid.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-intesaid.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-timid.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-infocertid.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item" href="#"><img class="img-dropdown-icon"
                                                    src="images/icons/spid-idp-namirialid.png"></a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item text-center" href="#">Maggiori informazioni</a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item text-center" href="#">Non hai SPID ?</a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item text-center" href="#">Serve aiuto ?</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- CIE -->
                <div class="tab-pane p-4 fade" id="tab3b" role="tabpanel" aria-labelledby="tab3b-tab">
                    <div class="col-md-3 mx-auto margin-bottom-section">
                        <div class="btn-example ">
                            <button type="button" class="btn btn-primary button-main dropdown-toggle"
                                data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <div class="">
                                    <span><img class="btn-divider-right" width="30px"
                                            src="images/icons/cie-icon.png" /></span>
                                    <span>Entra con CIE</span>
                                </div>
                            </button>
                            <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">
                                <div class="link-list-wrapper">
                                    <ul class="link-list">
                                        <li><a class="list-item text-center" href="#">Accedi</li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item text-center" href="#">Serve aiuto ?</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5 mx-auto text-left border-description-styled">
                        <h4>Cos'è la CIE?</h4>
                        <p>La CIE (Carta d'identità elettronica) è il nuovo documento d'identità in Italia. È rilasciata
                            sia ai cittadini italiani che stranieri (UE o extra-UE).
                            Oltre alle funzioni della precedente carta, permette l'accesso ai servizi digitali della
                            Pubblica Amministrazione come previsto dalla normativa. L'accesso può avvenire:</p>
                        <ul class="list">
                            <li>da PC (utilizzando un apposito lettore NFC)</li>
                            <li>da smartphone o tablet (dotati di tecnologia NFC, sistema operativo Android 6.x o
                                superiore e dell'applicazione "CIE ID" del Poligrafico)</li>
                        </ul>
                        <p>Si precisa che le CIE valide per l'accesso sono solo quelle rilasciate a partire da luglio
                            2016 con numero seriale, presente in alto a destra sulla carta, che inizia con la sigla
                            "CA".</p>
                        <span class="divider"></span>
                        <p><a class="list-item text-center" href="#">Maggiori informazioni</a></p>
                        <p><a class="list-item text-center" href="#">Non hai la CIE ?</a></p>
                    </div>
                </div>
                <!-- CNS -->
                <div class="tab-pane p-4 fade" id="tab4b" role="tabpanel" aria-labelledby="tab4b-tab">
                    <div class="col-md-3 mx-auto margin-bottom-section">
                        <div class="btn-example ">
                            <button type="button" class="btn btn-primary button-main dropdown-toggle"
                                data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <div class="">
                                    <span><img width="30px" src="images/icons/cns-icon.png" /></span>
                                    <span>Entra con CNS</span>
                                </div>
                            </button>
                            <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">
                                <div class="link-list-wrapper">
                                    <ul class="link-list">
                                        <li><a class="list-item text-center" href="#">Accedi</a></li>
                                        <li><span class="divider"></span></li>
                                        <li><a class="list-item text-center" href="#">Serve aiuto ?</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5 mx-auto text-left border-description-styled">
                        <h4>Cos'è la CNS?</h4>
                        <p>Lorem ipsum sit dolor amet, Lorem ipsum sit dolor amet
                            Lorem ipsum sit dolor amet Lorem ipsum sit dolor amet
                            Lorem ipsum sit dolor amet Lorem ipsum sit dolor amet</p>
                        <span class="divider"></span>
                        <p><a class="list-item text-center" href="#">Maggiori informazioni</a></p>
                        <p><a class="list-item text-center" href="#">Non hai la CNS ?</a></p>
                    </div>
                </div>
				<!-- FACEBOOK -->
                <% if(hasFacebookAuthenticator) { %>
                <div class="tab-pane p-4 fade" id="tab5b" role="tabpanel" aria-labelledby="tab5b-tab">
                    <div class="col-md-3 mx-auto margin-bottom-section">
                        <div class="btn-example ">
                            <button type="button" class="btn btn-primary button-main dropdown-toggle"
                                data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" id="loginWithFacebook">
                                <div class="">
                                    <span>Entra con Facebook</span>
                                </div>
                            </button>
                        </div>
                    </div>
                </div>
				<% } %>
            </div>
            <!-- end tabs-->
        </div>
    </div>
    <!-- footer -->
    <footer></footer>
    <!-- end footer -->

    <!-- script js -->
    <script src="js/jquery-1.7.1.min.js"></script>
    <script src="js/bootstrap-italia.bundle.min.js"></script>
    <!-- end script js -->
<!-- SPID -->
<script>
$(document).ready(function(){
    var rootList = $("#spid-idp-list-large-root-post");
    var idpList = rootList.children(".spid-idp-button-link");
    var lnkList = rootList.children(".spid-idp-support-link");
    while (idpList.length) {
        rootList.append(idpList.splice(Math.floor(Math.random() * idpList.length), 1)[0]);
    }
    rootList.append(lnkList);
    $("#spid_idp_access").submit(function (e){
    	return false;
    });
    $("#spid_idp_access button").click(function(e){
    	handleNoDomain($(this).attr("name"), 'SAMLSSOAuthenticator');
    	return false;
    });
    <% if(hasFacebookAuthenticator) {
    	String facebookIdp = idpAuthenticatorMapping.entrySet().stream().filter(es -> FACEBOOK_AUTHENTICATOR.equalsIgnoreCase(es.getValue())).findFirst().get().getKey();
    %>
    $("#loginWithFacebook").click(function(e) {
    	handleNoDomain('<%=facebookIdp%>', '<%=FACEBOOK_AUTHENTICATOR%>');
    });
    <% } %>
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

    <%
        private boolean isIdentifierFirstLogin(String inputType) {
            return "idf".equalsIgnoreCase(inputType);
        }
    %>

    </body>
    </html>
