import { useState, useEffect } from "react";
import { PublicClientApplication } from "@azure/msal-browser";
import { loginUser, loginWithMicrosoft, loginWithGoogle, registerUser } from "../api/api";
import { useNavigate } from "react-router-dom";
import { captureBrowserLocation } from "../utils/locationCapture";

let msalInstanceSingleton = null;
let msalInteractionLock = false;
const MSAL_LAST_REDIRECT_STATE_KEY = "msal_last_redirect_state";

function clearMsalInteractionState() {
  const clearKeys = (storage) => {
    const keysToRemove = [];
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (key && key.toLowerCase().includes("interaction.status")) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => storage.removeItem(key));
  };

  clearKeys(sessionStorage);
  clearKeys(localStorage);
}

function getMsalInstance(clientId, tenantId) {
  if (!msalInstanceSingleton) {
    msalInstanceSingleton = new PublicClientApplication({
      auth: {
        clientId,
        authority: `https://login.microsoftonline.com/${tenantId}`,
        redirectUri: window.location.origin
      },
      cache: {
        cacheLocation: "sessionStorage"
      }
    });
  }

  return msalInstanceSingleton;
}

const loadGoogleScript = () => {
  return new Promise((resolve) => {
    if (window.google?.accounts?.id) {
      resolve();
      return;
    }

    const existingScript = document.querySelector('script[src="https://accounts.google.com/gsi/client"]');
    if (existingScript) {
      existingScript.addEventListener("load", () => resolve(), { once: true });
      return;
    }

    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    document.head.appendChild(script);
  });
};

const handleGoogleSignIn = async (credentialResponse, navigate, setGoogleError) => {
  if (!credentialResponse?.credential) {
    setGoogleError("Google Sign-In failed: No credential received.");
    return;
  }

  try {
    setGoogleError("");
    
    // Capture browser location for login tracking
    const browserLocation = await captureBrowserLocation();
    
    const result = await loginWithGoogle(credentialResponse.credential, browserLocation);

    if (!result.success || !result.user?.access_token) {
      setGoogleError(result.message || "Google Sign-In failed.");
      return;
    }

    const data = result.user;
    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("refresh_token", data.refresh_token);
    localStorage.setItem("role", data.role);
    localStorage.setItem("username", data.username);
    localStorage.setItem("loginType", "google");
    window.dispatchEvent(new Event("login"));

    if (data.role === "admin" || data.role === "superadmin") {
      navigate("/admin");
    } else {
      navigate("/dashboard");
    }
  } catch (err) {
    setGoogleError(err?.message || "Google Sign-In failed.");
  }
};

function Login() {
  const [rightPanelActive, setRightPanelActive] = useState(false);

  // Login form
  const [loginForm, setLoginForm] = useState({
    email: "",
    password: "",
    loginType: "company"
  });

  // Register form
  const [registerForm, setRegisterForm] = useState({
    username: "",
    name: "",
    companyEmail: "",
    personalEmail: "",
    password: "",
    confirmPassword: "",
    photo: null,
    photoPreview: null
  });

  const [msg, setMsg] = useState("");
  const [msalBusy, setMsalBusy] = useState(false);
  const [googleError, setGoogleError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    let isMounted = true;

    async function processMicrosoftRedirect() {
      const clientId = import.meta.env.VITE_MICROSOFT_CLIENT_ID || "b6478038-e944-4299-abf0-5eafa75416c2";
      const tenantId = import.meta.env.VITE_MICROSOFT_TENANT_ID || "common";

      if (!clientId) {
        return;
      }

      try {
        const msalInstance = getMsalInstance(clientId, tenantId);
        await msalInstance.initialize();
        const redirectResponse = await msalInstance.handleRedirectPromise();

        if (!redirectResponse?.idToken || !isMounted) {
          return;
        }

        if (redirectResponse.state) {
          const lastState = sessionStorage.getItem(MSAL_LAST_REDIRECT_STATE_KEY);
          if (lastState === redirectResponse.state) {
            return;
          }
          sessionStorage.setItem(MSAL_LAST_REDIRECT_STATE_KEY, redirectResponse.state);
        }

        // Capture browser location for login tracking
        const browserLocation = await captureBrowserLocation();
        
        const res = await loginWithMicrosoft(redirectResponse.idToken, browserLocation);
        if (!res.success || !res.user?.access_token) {
          if (isMounted) {
            setMsg(res.message || "Microsoft login failed ❌");
          }
          return;
        }

        if (isMounted) {
          setMsg("Microsoft Login Successful ✔");
          localStorage.setItem("role", res.user.role);
          localStorage.setItem("username", res.user.username);
          localStorage.setItem("loginType", "microsoft");
          window.dispatchEvent(new Event("login"));

          if (res.user.role === "admin" || res.user.role === "superadmin") {
            navigate("/admin");
          } else {
            navigate("/dashboard");
          }
        }
      } catch (error) {
        console.error("Microsoft redirect login error:", error);
        if (isMounted) {
          setMsg(`Microsoft login failed - ${error.message}`);
        }
      }
    }

    processMicrosoftRedirect();

    return () => {
      isMounted = false;
    };
  }, [navigate]);

  async function handleMicrosoftSignIn() {
    if (msalBusy || msalInteractionLock) {
      setMsg("Microsoft login is already in progress. Please complete the popup.");
      return;
    }

    const clientId = import.meta.env.VITE_MICROSOFT_CLIENT_ID || "b6478038-e944-4299-abf0-5eafa75416c2";
    const tenantId = import.meta.env.VITE_MICROSOFT_TENANT_ID || "common";

    if (!clientId) {
      setMsg("Microsoft Sign-In is not configured. Set VITE_MICROSOFT_CLIENT_ID in frontend/.env ❌");
      return;
    }

    try {
      msalInteractionLock = true;
      setMsalBusy(true);
      const msalInstance = getMsalInstance(clientId, tenantId);
      await msalInstance.initialize();
      clearMsalInteractionState();
      sessionStorage.removeItem(MSAL_LAST_REDIRECT_STATE_KEY);
      await msalInstance.loginRedirect({
        scopes: ["openid", "profile", "email"],
        prompt: "select_account"
      });
    } catch (error) {
      console.error("Microsoft login error:", error);

      if (error?.errorCode === "interaction_in_progress") {
        clearMsalInteractionState();
        setMsg("Microsoft login was interrupted. Please wait 2 seconds and click once.");
        return;
      }

      if (error?.errorCode === "no_token_request_cache_error") {
        setMsg("Microsoft login session expired. Please try Sign in with Microsoft again.");
        return;
      }

      if (error?.errorCode === "block_nested_popups") {
        setMsg("Popup blocked by browser context. Retrying with redirect login...");
        try {
          const msalInstance = getMsalInstance(clientId, tenantId);
          await msalInstance.loginRedirect({
            scopes: ["openid", "profile", "email"],
            prompt: "select_account"
          });
          return;
        } catch (redirectError) {
          setMsg(`Microsoft login failed - ${redirectError.message}`);
          return;
        }
      }

      setMsg(`Microsoft login failed - ${error.message}`);
    } finally {
      setMsalBusy(false);
      msalInteractionLock = false;
    }
  }

  // Auto redirect if already logged in
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (token) navigate("/dashboard");
  }, [navigate]);

  useEffect(() => {
    let isMounted = true;

    const initGoogle = async () => {
      const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;

      if (!clientId || clientId === "your_google_client_id_here" || clientId.includes("undefined")) {
        if (isMounted) setGoogleError("Google Sign-In not configured. Set VITE_GOOGLE_CLIENT_ID in frontend/.env");
        return;
      }

      try {
        await loadGoogleScript();

        if (!window.google?.accounts?.id) {
          if (isMounted) setGoogleError("Google Sign-In library failed to load.");
          return;
        }

        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: (credentialResponse) => {
            handleGoogleSignIn(credentialResponse, navigate, setGoogleError);
          }
        });

        const buttonElement = document.getElementById("google-signin-button");
        if (buttonElement) {
          buttonElement.innerHTML = "";
          window.google.accounts.id.renderButton(buttonElement, {
            theme: "outline",
            size: "large",
            width: 300,
            logo_alignment: "center"
          });
        }
      } catch (err) {
        if (isMounted) setGoogleError(err?.message || "Google Sign-In initialization failed.");
      }
    };

    initGoogle();

    return () => {
      isMounted = false;
    };
  }, [navigate]);

  // Email validation helper
  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  // Password validation helper (minimum 8 characters)
  function isValidPassword(password) {
    return password.length >= 8;
  }

  // UI switch animation
  const handleSignUpClick = () => setRightPanelActive(true);
  const handleSignInClick = () => setRightPanelActive(false);

  // ---------------- LOGIN SUBMIT ----------------
  async function handleLoginSubmit(e) {
    e.preventDefault();

    if (!loginForm.email) return setMsg("Email is required ❌");
    if (!isValidEmail(loginForm.email)) return setMsg("Invalid email format ❌");
    if (!loginForm.password) return setMsg("Password is required ❌");

    try {
      // Capture browser location for login tracking
      const browserLocation = await captureBrowserLocation();
      
      // No device UUID needed - agent handles device authentication separately
      const payload = {
        username: loginForm.email, // backend expects username but we pass email
        password: loginForm.password,
        browser_location: browserLocation
      };

      const res = await loginUser(payload);

      if (res.success && res.user.access_token) {
        setMsg("Login Successful ✔");

        localStorage.setItem("role", res.user.role);
        localStorage.setItem("username", res.user.username);
        localStorage.setItem("loginType", loginForm.loginType);

        window.dispatchEvent(new Event("login"));

        // redirect based on role
        if (res.user.role === "admin" || res.user.role === "superadmin") {
          navigate("/admin");
        } else {
          navigate("/dashboard");
        }

      } else {
        setMsg(res.message || "Login Failed ❌");
      }
    } catch (error) {
      console.error("Login error:", error);
      setMsg("Login failed - " + error.message);
    }
  }

  // ---------------- REGISTER SUBMIT ----------------
  async function handleRegisterSubmit(e) {
    e.preventDefault();

    // Validation
    if (!registerForm.username) return setMsg("Username is required ❌");
    if (!registerForm.name) return setMsg("Name is required ❌");
    if (!registerForm.companyEmail) return setMsg("Company email is required ❌");
    if (!registerForm.personalEmail) return setMsg("Personal email is required ❌");
    if (!isValidEmail(registerForm.companyEmail)) return setMsg("Invalid company email format ❌");
    if (!isValidEmail(registerForm.personalEmail)) return setMsg("Invalid personal email format ❌");
    if (!registerForm.password) return setMsg("Password is required ❌");
    if (!isValidPassword(registerForm.password)) return setMsg("Password must be at least 8 characters ❌");
    if (registerForm.password !== registerForm.confirmPassword)
      return setMsg("Passwords do not match ❌");

    // Create FormData to handle file upload
    const formData = new FormData();
    formData.append("username", registerForm.username);
    formData.append("name", registerForm.name);
    formData.append("company_email", registerForm.companyEmail);
    formData.append("personal_email", registerForm.personalEmail);
    formData.append("password", registerForm.password);
    
    // Add photo if provided
    if (registerForm.photo) {
      formData.append("photo", registerForm.photo);
    }

    try {
      const res = await fetch("http://localhost:8000/register", {
        method: "POST",
        body: formData  // Don't set Content-Type header - browser will set it with boundary
      });

      const data = await res.json();

      if (res.ok && data.id) {
        setMsg("Registration Successful 🎉 Login now!");
        setRightPanelActive(false);
        setRegisterForm({
          username: "",
          name: "",
          companyEmail: "",
          personalEmail: "",
          password: "",
          confirmPassword: "",
          photo: null,
          photoPreview: null
        });
      } else {
        setMsg(data.detail || "Registration Failed ❌");
      }
    } catch (error) {
      console.error("Registration error:", error);
      setMsg("Registration failed - " + error.message);
    }
  }

  // Handle photo selection
  function handlePhotoChange(e) {
    const file = e.target.files[0];
    if (file) {
      // Validate file size (max 5MB)
      if (file.size > 5 * 1024 * 1024) {
        setMsg("Photo size must be less than 5MB ❌");
        return;
      }

      // Create preview
      const reader = new FileReader();
      reader.onloadend = () => {
        setRegisterForm({
          ...registerForm,
          photo: file,
          photoPreview: reader.result
        });
      };
      reader.readAsDataURL(file);
      setMsg("");
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-orb orb-1" aria-hidden="true" />
      <div className="auth-orb orb-2" aria-hidden="true" />
      <div className="auth-grid" aria-hidden="true" />

      <div
        className={`container auth-card ${rightPanelActive ? "right-panel-active" : ""}`}
        id="container"
      >
        {/* REGISTER FORM */}
        <div className="form-container sign-up-container">
          <form onSubmit={handleRegisterSubmit}>
            <h1>Create Account</h1>
            <p className="auth-subtitle">Build a trusted profile for secure access.</p>
          <input type="text" placeholder="Username"
            value={registerForm.username}
            onChange={e=>setRegisterForm({...registerForm, username:e.target.value})} required/>
          <input type="text" placeholder="Name"
            value={registerForm.name}
            onChange={e=>setRegisterForm({...registerForm, name:e.target.value})} required/>
          <input type="email" placeholder="Company Email"
            value={registerForm.companyEmail}
            onChange={e=>setRegisterForm({...registerForm, companyEmail:e.target.value})} required/>
          <input type="email" placeholder="Personal Email"
            value={registerForm.personalEmail}
            onChange={e=>setRegisterForm({...registerForm, personalEmail:e.target.value})} required/>
          <input type="password" placeholder="Password"
            value={registerForm.password}
            onChange={e=>setRegisterForm({...registerForm, password:e.target.value})} required/>
          <input type="password" placeholder="Confirm Password"
            value={registerForm.confirmPassword}
            onChange={e=>setRegisterForm({...registerForm, confirmPassword:e.target.value})} required/>
          
          {/* Photo Upload */}
          <div style={{
            width: "100%",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "10px",
            margin: "15px 0"
          }}>
            {registerForm.photoPreview && (
              <div style={{
                width: "100px",
                height: "100px",
                borderRadius: "50%",
                border: "2px solid var(--accent)",
                overflow: "hidden",
                display: "flex",
                alignItems: "center",
                justifyContent: "center"
              }}>
                <img 
                  src={registerForm.photoPreview} 
                  alt="preview"
                  style={{ width: "100%", height: "100%", objectFit: "cover" }}
                />
              </div>
            )}
            <label style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              cursor: "pointer",
              fontSize: "14px",
              color: "var(--accent)",
              padding: "8px 16px",
              border: "1px solid var(--accent)",
              borderRadius: "4px",
              transition: "all 0.3s"
            }}>
              📷 Choose Photo (Optional)
              <input 
                type="file"
                accept="image/*"
                onChange={handlePhotoChange}
                style={{ display: "none" }}
              />
            </label>
            {!registerForm.photoPreview && (
              <small style={{ color: "var(--text-muted)", fontSize: "12px" }}>
                No photo selected - avatar will be generated
              </small>
            )}
          </div>
          
          <button type="submit">Sign Up</button>
        </form>
      </div>

      {/* LOGIN FORM */}
      <div className="form-container sign-in-container">
        <form onSubmit={handleLoginSubmit}>
          <h1>Sign in</h1>
          <p className="auth-subtitle">Continue into your Zero Trust workspace.</p>

          <button type="button" onClick={handleMicrosoftSignIn} disabled={msalBusy} style={{ marginBottom: "10px" }}>
            {msalBusy ? "Signing in with Microsoft..." : "Sign in with Microsoft"}
          </button>
          
          <div 
            id="google-signin-button" 
            style={{ 
              margin: "18px 0",
              display: "flex",
              justifyContent: "center"
            }}
          />

          {googleError && (
            <div style={{
              marginTop: "8px",
              fontSize: "12px",
              color: "#b71c1c",
              textAlign: "center"
            }}>
              {googleError}
            </div>
          )}
          
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            margin: "16px 0",
            color: "var(--text-muted)"
          }}>
            <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
            <span style={{ fontSize: "12px" }}>OR</span>
            <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
          </div>

          <input type="email" placeholder="Email"
            value={loginForm.email}
            onChange={e=>setLoginForm({...loginForm, email:e.target.value})} required/>
          
          {/* Login email type selection */}
          <select value={loginForm.loginType}
            onChange={e=>setLoginForm({...loginForm, loginType:e.target.value})}>
            <option value="company">Company Email</option>
            <option value="personal">Personal Email</option>
          </select>

          <input type="password" placeholder="Password"
            value={loginForm.password}
            onChange={e=>setLoginForm({...loginForm, password:e.target.value})} required/>

          <button type="submit">Sign In</button>
        </form>
      </div>

      {/* UI Panels */}
      <div className="overlay-container">
        <div className="overlay">
          <div className="overlay-panel overlay-left">
            <span className="auth-badge">Secure Session</span>
            <h1>Welcome Back!</h1>
            <p className="auth-hero">Review alerts, verify devices, and keep control.</p>
            <button className="ghost" onClick={handleSignInClick}>Sign In</button>
          </div>
          <div className="overlay-panel overlay-right">
            <span className="auth-badge">New Access</span>
            <h1>Hello Friend!</h1>
            <p className="auth-hero">Create your profile and start monitoring securely.</p>
            <button className="ghost" onClick={handleSignUpClick}>Sign Up</button>
          </div>
        </div>
      </div>

      <p className="auth-message">{msg}</p>
    </div>
  </div>
  );
}

export default Login;
