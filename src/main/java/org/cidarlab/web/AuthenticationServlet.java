package org.cidarlab.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.JSONObject;

/**
 * The AuthenticationServlet serves POST requests regarding
 * SIGNUP, LOGIN, and LOGOUT for Web Applications.
 * It also servers GET requests through forward the user 
 * to the index.html page.
 * 
 * @author Ernst Oberortner
 */
public class AuthenticationServlet 
	extends HttpServlet {

	private static final long serialVersionUID = -1579220291590687064L;
	
	private static final String USER_DB_NAME = "CIDAR";
	private static org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger("AuthenticationServlet");
		
	// a reference to an instance 
	// of the CIDAR authenticator
	private Authenticator auth;
	
	@Override
	public void init(ServletConfig config) 
			throws ServletException {
		
	    super.init(config);
	    
	    this.auth = new Authenticator(USER_DB_NAME);
	    
	    // set a system property such that Simple Logger will include timestamp
        System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
        // set a system property such that Simple Logger will include timestamp in the given format
        System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "dd-MM-yy HH:mm:ss");

        // set minimum log level for SLF4J Simple Logger at warn
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
        
        LOGGER.warn("[AuthenticationServlet] loaded!");	    
	}
	
    /**
     * Handles the HTTP
     * <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

    	JSONObject jsonResponse = new JSONObject();
    	
        try {
        	
        	// get the username and password parameter values 
        	// from the request
        	String command = request.getParameter(AuthenticationConstants.COMMAND);
        	String username = request.getParameter(AuthenticationConstants.USERNAME);
        	String password = request.getParameter(AuthenticationConstants.PASSWORD);
        	
        	/*
        	 * SIGNUP Request
        	 */
        	if(AuthenticationConstants.SIGNUP.equals(command)) {
        		
        		// register the user
            	this.auth.register(username, password);
            	
            	// we automatically login the user, 
            	// i.e. we do some session management 
            	this.login(request, response, username);

            /*
             * LOGIN Request
             */
        	} else if(AuthenticationConstants.LOGIN.equals(command)) {
        		
        		// first, we check if the user exists and 
        		// if the passwords match up
        		boolean bLogin = this.auth.login(username, password);
        		
        		if(bLogin) {
        			
        			// invalidate the session
        			this.invalidateSession(request);
        			
            		// delete the USER_COOKIE
        			this.eraseUserCookie(request, response);

        			// login the user including session management
                	this.login(request, response, username);
        		}
        		
        	/*
        	 *  LOGOUT Request
        	 */
        	} else if(AuthenticationConstants.LOGOUT.equals(command)) {
        		
        		// we just invalidate the user's session
        		this.invalidateSession(request);
        		
        		// and we delete the USER_COOKIE
    			this.eraseUserCookie(request, response);

        		
        	/*
        	 * Invalid Request	
        	 */
            } else {
            	LOGGER.warn("Invalid login! user: " + username + ", password: " + password);
            	throw new AuthenticationException("Invalid Request!");
            }
        	
        	jsonResponse.put("status", "good");
        	
        } catch(Exception e) {
        	
    		LOGGER.warn(e.getMessage());
    		
    		jsonResponse.put("status", "exception");
    		jsonResponse.put("result", e.getMessage());
        } 

        /*
         * write the response
         */
    	PrintWriter out = response.getWriter();
    	response.setContentType("application/json");
        
    	out.write(jsonResponse.toString());
    	
    	out.flush();
        out.close();
    }
    
    /**
     * The invalidateSession(HttpServletRequest) method removes 
     * all attributes from the request's session, i.e. user and eugenelab
     * information.
     * 
     * @param request
     */
    private void invalidateSession(HttpServletRequest request) {
    	
    	if(null != request && null != request.getSession()) {
    		
			// the session expires immediately
			request.getSession().setMaxInactiveInterval(1);

			// we remove the user information
			request.getSession().removeAttribute(AuthenticationConstants.USER_COOKIE);

			// delete the request's cookies
			// finally, we invalidate it
    		request.getSession().invalidate();
    	}
    }
    
    /**
     * The eraseCookie method deletes the cookie that contains 
     * user-information
     *  
     * @param request ... the request
     * @param response .. the response
     */
    private void eraseUserCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
            	if(AuthenticationConstants.USER_COOKIE.equals(cookies[i].getName())) {
	                cookies[i].setValue("");
	                cookies[i].setPath("/");
	                cookies[i].setMaxAge(0);
	                response.addCookie(cookies[i]);
            	}
            }
        }
    }
    
    
    private void login(HttpServletRequest request, HttpServletResponse response, String user) {

		/*-------------------------------
		 * VALID AUTHENTICATION 
		 *-------------------------------*/  
		
		// we create a session
		HttpSession session = request.getSession(true);
		
		// put the username into it
        session.setAttribute(AuthenticationConstants.USER_COOKIE, user);

        // a session expires after 60 mins
        session.setMaxInactiveInterval(60 * 60);
        
        response.addCookie(new Cookie(AuthenticationConstants.USER_COOKIE, user));
    }
    	


    /**
     * Handles the HTTP
     * <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processGetRequest(request, response);
    }

    /**
     * Processes requests for HTTP
     * <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processGetRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
    	
        PrintWriter out = response.getWriter();

        response.setContentType("text/html;charset=UTF-8");
        response.sendRedirect("index.html");
        
        
        out.flush();
        out.close();
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "CIDAR-Lab Servlet for SIGNUP, LOGIN, and LOGOUT for Web Applications";
    }

}