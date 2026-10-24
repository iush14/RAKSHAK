import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  Info, 
  Code, 
  Box, 
  Lock, 
  ShieldCheck, 
  Sparkles, 
  Infinity as InfinityIcon, 
  Zap, 
  Loader2, 
  AlertCircle,
  X,
  CheckCircle2,
  ArrowRight
} from 'lucide-react';
import { API_BASE_URL } from '@/services/api';
import { GithubIcon } from '@/components/ui/GithubIcon';
import { auth, googleProvider } from '@/firebase';
import { signInWithPopup } from 'firebase/auth';
import { useSecurity } from '@/context/SecurityContext';

interface AuthPageProps {
  initialTab?: 'login' | 'register';
}

export default function Login({ initialTab = 'login' }: AuthPageProps) {
  const navigate = useNavigate();
  const { checkAuthStatus } = useSecurity();
  const [activeTab, setActiveTab] = useState<'login' | 'register'>(initialTab);

  // Sync state if prop changes
  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

  // UX Feedback States
  const [isLoading, setIsLoading] = useState(false);
  const [loadingProvider, setLoadingProvider] = useState<'google' | 'github' | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<{ title: string; desc: string; type: 'success' | 'info' | 'error' } | null>(null);

  // Google OAuth via Firebase Popup (with 8s safety timeout against hanging popups)
  const handleGoogleAuth = async () => {
    setIsLoading(true);
    setLoadingProvider('google');
    setErrorMessage(null);
    try {
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), 8000)
      );
      await Promise.race([signInWithPopup(auth, googleProvider), timeoutPromise]);
      setToastMessage({
        title: 'Authentication Successful',
        desc: 'Establishing secure Rakshak workspace session...',
        type: 'success',
      });
      await checkAuthStatus();
      setTimeout(() => {
        navigate('/dashboard');
      }, 400);
    } catch (err: any) {
      console.error('Google Auth Error:', err);
      if (err?.message === 'timeout') {
        setErrorMessage('Google sign-in timed out. Popup was blocked or restricted. Please click "Continue with GitHub" or "Explore Demo Workspace" below.');
      } else if (err.code === 'auth/popup-closed-by-user') {
        setErrorMessage('Sign-in cancelled. The Google popup was closed before completion.');
      } else if (err.code === 'auth/popup-blocked') {
        setErrorMessage('Popup was blocked by your browser. Please click "Continue with GitHub" below.');
      } else if (err.code === 'auth/cancelled-popup-request') {
        // Ignored duplicate
      } else if (err.code === 'auth/unauthorized-domain') {
        setErrorMessage(`Domain not authorized in Firebase. Please click "Continue with GitHub" or "Explore Demo Workspace" below.`);
      } else {
        setErrorMessage(err.message || 'Google sign-in unavailable. Please click "Continue with GitHub" or "Explore Demo Workspace" below.');
      }
    } finally {
      setIsLoading(false);
      setLoadingProvider(null);
    }
  };

  // GitHub OAuth via FastAPI backend (Direct redirect, no popups, works 100% on Render)
  const handleGithubAuth = () => {
    setIsLoading(true);
    setLoadingProvider('github');
    setErrorMessage(null);
    window.location.href = `${API_BASE_URL}/auth/github`;
  };

  // Instant Guest / Demo workspace access
  const handleGuestAccess = () => {
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen bg-[#06000E] text-[#F5F3FF] flex flex-col justify-between relative overflow-hidden font-sans select-none">
      
      {/* Background Ambient Glows */}
      <div className="absolute top-[-10%] left-[20%] w-[650px] h-[650px] bg-[#7c3aed]/18 rounded-full mix-blend-screen filter blur-[170px] pointer-events-none" />
      <div className="absolute top-[30%] right-[-10%] w-[650px] h-[650px] bg-[#ec4899]/18 rounded-full mix-blend-screen filter blur-[170px] pointer-events-none" />
      <div className="absolute bottom-[-10%] left-[10%] w-[700px] h-[700px] bg-[#c026d3]/12 rounded-full mix-blend-screen filter blur-[180px] pointer-events-none" />
      
      {/* Subtle Grid Overlay */}
      <div className="absolute inset-0 bg-[radial-gradient(#2A1240_1px,transparent_1px)] [background-size:28px_28px] opacity-30 pointer-events-none" />

      {/* Floating Toast Notification */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed top-5 left-1/2 -translate-x-1/2 z-50 max-w-md w-full px-4"
          >
            <div className={`p-4 rounded-xl border backdrop-blur-md shadow-2xl flex items-start justify-between gap-3 ${
              toastMessage.type === 'success' 
                ? 'bg-[#12051F]/90 border-emerald-500/50 text-emerald-300 shadow-[0_0_25px_rgba(16,185,129,0.3)]' 
                : 'bg-[#12051F]/90 border-purple-500/50 text-purple-200 shadow-[0_0_25px_rgba(168,85,247,0.3)]'
            }`}>
              <div className="flex items-start gap-3">
                {toastMessage.type === 'success' ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
                ) : (
                  <Info className="w-5 h-5 text-purple-400 mt-0.5 shrink-0" />
                )}
                <div>
                  <h4 className="text-sm font-bold">{toastMessage.title}</h4>
                  <p className="text-xs text-zinc-300 mt-0.5">{toastMessage.desc}</p>
                </div>
              </div>
              <button 
                onClick={() => setToastMessage(null)}
                className="text-zinc-400 hover:text-white transition-colors"
              >
                <X size={16} />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 1. TOP HEADER */}
      <header className="w-full max-w-7xl mx-auto px-6 py-6 flex items-center justify-between z-20">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="relative w-10 h-10 flex items-center justify-center">
            <Shield className="w-7 h-7 text-[#A855F7] group-hover:scale-105 transition-transform" />
            <span className="absolute inset-0 flex items-center justify-center text-[10px] font-black text-white">R</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl font-black tracking-wider text-white-pink-gradient">
                RAKSHAK
              </span>
              <span className="hidden sm:inline-block text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded-full bg-[#A855F7]/10 text-[#A855F7] border border-[#A855F7]/30">
                AI DevSecOps
              </span>
            </div>
            <p className="text-[11px] text-[#C4B5FD]/70 hidden md:block">
              AI-Powered DevSecOps Threat Detection
            </p>
          </div>
        </Link>

        <div className="flex items-center gap-2 sm:gap-3">
          <Button
            variant="outline"
            onClick={() => navigate('/')}
            className="rounded-full bg-[#12051F]/60 border-[#2A1240] text-[#C4B5FD] hover:text-white hover:border-[#A855F7]/60 hover:bg-[#A855F7]/10 px-4 py-2 text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-[0_0_15px_rgba(168,85,247,0.15)]"
          >
            <span>&larr; Home</span>
          </Button>

          <Button
            variant="outline"
            onClick={() => navigate('/about')}
            className="rounded-full bg-[#12051F]/60 border-[#2A1240] text-[#C4B5FD] hover:text-white hover:border-[#A855F7]/60 hover:bg-[#A855F7]/10 px-4 sm:px-5 py-2 text-xs flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(168,85,247,0.15)]"
          >
            <Info size={14} className="text-[#EC4899]" />
            <span className="hidden sm:inline">About Rakshak</span>
            <span className="sm:hidden">About</span>
          </Button>
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <main className="w-full max-w-7xl mx-auto px-4 sm:px-6 py-4 flex-1 flex flex-col justify-center items-center z-10 gap-8">
        
        {/* 2. HERO SECTION */}
        <section className="text-center max-w-3xl mx-auto flex flex-col items-center">
          {/* Centered Large Glowing Shield Logo */}
          <motion.div 
            initial={{ opacity: 0, scale: 0.88 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, ease: "easeOut" }}
            className="relative mb-5 flex items-center justify-center"
          >
            {/* Animated Glow Rings */}
            <div className="absolute w-28 h-28 rounded-full border border-[#A855F7]/40 animate-[spin_14s_linear_infinite]" />
            <div className="absolute w-36 h-36 rounded-full border border-[#EC4899]/30 border-dashed animate-[spin_20s_linear_infinite_reverse]" />
            <div className="absolute w-44 h-44 rounded-full bg-gradient-to-tr from-[#7c3aed]/25 via-[#a855f7]/20 to-[#ec4899]/25 blur-2xl animate-pulse" />

            {/* Central Shield Icon */}
            <div className="relative z-10 p-3.5 flex items-center justify-center">
              <Shield className="w-20 h-20 text-[#A855F7] filter drop-shadow-[0_0_30px_rgba(168,85,247,0.9)]" />
              <span className="absolute font-black text-3xl text-white drop-shadow-[0_0_15px_rgba(255,255,255,0.95)]">
                R
              </span>
            </div>
          </motion.div>

          {/* Title */}
          <motion.h1 
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight mb-2"
          >
            <span className="text-white-pink-gradient">
              RAKSHAK
            </span>
          </motion.h1>

          {/* Subtitle */}
          <motion.h2 
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg sm:text-xl font-bold text-[#A855F7] mb-2"
          >
            AI-Powered DevSecOps Threat Detection Platform
          </motion.h2>

          {/* Description Lines */}
          <motion.div 
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="text-xs sm:text-sm text-[#C4B5FD]/85 max-w-xl space-y-1 font-sans"
          >
            <p>Connect your GitHub repository & scan code for security threats.</p>
            <p className="text-white font-medium">Automated vulnerability analysis & AI risk calculation.</p>
          </motion.div>
        </section>

        {/* MAIN CONTENT GRID */}
        <div className="w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-center max-w-6xl mx-auto">
          
          {/* SECURITY FEATURE CARDS (LEFT SIDE) */}
          <motion.div 
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="lg:col-span-3 space-y-3.5 order-2 lg:order-1"
          >
            <div className="hidden lg:block text-xs uppercase tracking-widest font-bold text-[#A855F7] mb-2 px-1">
              Core Protection
            </div>

            {/* Card 1 */}
            <div className="p-3.5 rounded-xl bg-[#12051F]/70 border border-[#2A1240] hover:border-[#A855F7]/60 hover:shadow-[0_0_20px_rgba(168,85,247,0.25)] transition-all flex items-start gap-3.5 group">
              <div className="p-2.5 rounded-lg bg-[#A855F7]/10 text-[#A855F7] border border-[#A855F7]/30 group-hover:scale-105 group-hover:bg-[#A855F7]/20 transition-all shrink-0">
                <Code size={18} />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white group-hover:text-[#EC4899] transition-colors">Code Scanning</h4>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-snug mt-0.5">Detect insecure code patterns</p>
              </div>
            </div>

            {/* Card 2 */}
            <div className="p-3.5 rounded-xl bg-[#12051F]/70 border border-[#2A1240] hover:border-[#A855F7]/60 hover:shadow-[0_0_20px_rgba(168,85,247,0.25)] transition-all flex items-start gap-3.5 group">
              <div className="p-2.5 rounded-lg bg-[#EC4899]/10 text-[#EC4899] border border-[#EC4899]/30 group-hover:scale-105 group-hover:bg-[#EC4899]/20 transition-all shrink-0">
                <Box size={18} />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white group-hover:text-[#EC4899] transition-colors">Dependency Scanning</h4>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-snug mt-0.5">Detect vulnerable packages</p>
              </div>
            </div>

            {/* Card 3 */}
            <div className="p-3.5 rounded-xl bg-[#12051F]/70 border border-[#2A1240] hover:border-[#A855F7]/60 hover:shadow-[0_0_20px_rgba(168,85,247,0.25)] transition-all flex items-start gap-3.5 group">
              <div className="p-2.5 rounded-lg bg-[#c026d3]/10 text-[#c026d3] border border-[#c026d3]/30 group-hover:scale-105 group-hover:bg-[#c026d3]/20 transition-all shrink-0">
                <Lock size={18} />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white group-hover:text-[#EC4899] transition-colors">Secret Detection</h4>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-snug mt-0.5">Detect leaked API keys & secrets</p>
              </div>
            </div>

            {/* Card 4 */}
            <div className="p-3.5 rounded-xl bg-[#12051F]/70 border border-[#2A1240] hover:border-[#A855F7]/60 hover:shadow-[0_0_20px_rgba(168,85,247,0.25)] transition-all flex items-start gap-3.5 group">
              <div className="p-2.5 rounded-lg bg-[#3b82f6]/10 text-[#3b82f6] border border-[#3b82f6]/30 group-hover:scale-105 group-hover:bg-[#3b82f6]/20 transition-all shrink-0">
                <ShieldCheck size={18} />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white group-hover:text-[#EC4899] transition-colors">AI Analysis</h4>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-snug mt-0.5">Intelligent explanations & risk summary</p>
              </div>
            </div>
          </motion.div>

          {/* CENTER AUTHENTICATION CARD (GOOGLE & GITHUB ONLY) */}
          <motion.div 
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="lg:col-span-6 order-1 lg:order-2 w-full max-w-md mx-auto"
          >
            <div className="bg-[#12051F]/85 backdrop-blur-xl border border-[#2A1240] hover:border-[#A855F7]/40 transition-all rounded-3xl p-6 sm:p-8 shadow-[0_0_50px_rgba(168,85,247,0.25)] relative overflow-hidden">
              
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-rakshak-gradient opacity-90" />

              {/* TABS: Login | Register */}
              <div className="flex justify-center border-b border-[#2A1240] mb-6 relative">
                <button
                  type="button"
                  onClick={() => { setActiveTab('login'); setErrorMessage(null); }}
                  className={`px-8 py-3 text-sm font-bold transition-all relative cursor-pointer ${
                    activeTab === 'login' ? 'text-white' : 'text-[#C4B5FD]/50 hover:text-[#C4B5FD]'
                  }`}
                >
                  Login
                  {activeTab === 'login' && (
                    <motion.div 
                      layoutId="activeTabUnderline" 
                      className="absolute bottom-0 left-0 right-0 h-[2px] bg-rakshak-gradient shadow-[0_0_10px_rgba(236,72,153,0.8)]" 
                    />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => { setActiveTab('register'); setErrorMessage(null); }}
                  className={`px-8 py-3 text-sm font-bold transition-all relative cursor-pointer ${
                    activeTab === 'register' ? 'text-white' : 'text-[#C4B5FD]/50 hover:text-[#C4B5FD]'
                  }`}
                >
                  Register
                  {activeTab === 'register' && (
                    <motion.div 
                      layoutId="activeTabUnderline" 
                      className="absolute bottom-0 left-0 right-0 h-[2px] bg-rakshak-gradient shadow-[0_0_10px_rgba(236,72,153,0.8)]" 
                    />
                  )}
                </button>
              </div>

              {/* Form Heading & Subtitle */}
              <div className="text-center mb-6">
                <h3 className="text-2xl font-black text-white">
                  {activeTab === 'login' ? 'Welcome Back!' : 'Get Started with Rakshak'}
                </h3>
                <p className="text-xs text-[#C4B5FD]/80 mt-1.5 leading-relaxed">
                  {activeTab === 'login' 
                    ? 'Authenticate using your enterprise identity provider to access the command center.' 
                    : 'Create your Rakshak security account in one click using Google or GitHub.'}
                </p>
              </div>

              {/* Inline Error Display */}
              {errorMessage && (
                <motion.div 
                  initial={{ opacity: 0, y: -5 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-5 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2.5"
                >
                  <AlertCircle size={16} className="text-red-400 shrink-0" />
                  <span className="leading-tight">{errorMessage}</span>
                </motion.div>
              )}

              {/* AUTHENTICATION OPTIONS */}
              <div className="space-y-3.5 my-2">
                
                {/* 1. CONTINUE WITH GITHUB (RECOMMENDED / BULLETPROOF DIRECT BACKEND OAUTH) */}
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleGithubAuth}
                  disabled={isLoading}
                  className="w-full h-12 bg-gradient-to-r from-[#2A0845] to-[#1B053A] hover:from-[#3B0764] hover:to-[#2A0845] text-white border-[#A855F7]/60 hover:border-[#A855F7] rounded-2xl text-xs font-bold transition-all shadow-[0_0_25px_rgba(168,85,247,0.35)] hover:shadow-[0_0_35px_rgba(168,85,247,0.5)] flex items-center justify-center gap-3 cursor-pointer group"
                >
                  {loadingProvider === 'github' ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin text-white" />
                      <span>Redirecting to GitHub...</span>
                    </>
                  ) : (
                    <>
                      <GithubIcon size={20} className="text-white shrink-0 group-hover:scale-110 transition-transform" />
                      <span className="font-semibold text-white">
                        {activeTab === 'login' ? 'Continue with GitHub (Recommended)' : 'Sign up with GitHub (Recommended)'}
                      </span>
                    </>
                  )}
                </Button>

                {/* 2. CONTINUE WITH GOOGLE */}
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleGoogleAuth}
                  disabled={isLoading}
                  className="w-full h-12 bg-white text-zinc-900 hover:bg-zinc-100 border-white/80 rounded-2xl text-xs font-bold transition-all shadow-[0_0_20px_rgba(255,255,255,0.15)] hover:shadow-[0_0_25px_rgba(255,255,255,0.3)] flex items-center justify-center gap-3 cursor-pointer group"
                >
                  {loadingProvider === 'google' ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin text-zinc-900" />
                      <span>Connecting with Google...</span>
                    </>
                  ) : (
                    <>
                      {/* Official Google G Logo */}
                      <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24">
                        <path
                          fill="#4285F4"
                          d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                        />
                        <path
                          fill="#34A853"
                          d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                        />
                        <path
                          fill="#FBBC05"
                          d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                        />
                        <path
                          fill="#EA4335"
                          d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                        />
                      </svg>
                      <span className="font-semibold text-zinc-900 group-hover:scale-[1.01] transition-transform">
                        {activeTab === 'login' ? 'Continue with Google' : 'Sign up with Google'}
                      </span>
                    </>
                  )}
                </Button>

                {/* 3. INSTANT DEMO / GUEST ACCESS */}
                <div className="relative flex py-2 items-center">
                  <div className="flex-grow border-t border-[#2A1240]"></div>
                  <span className="flex-shrink mx-4 text-[10px] text-[#C4B5FD]/50 uppercase tracking-wider">or instant preview</span>
                  <div className="flex-grow border-t border-[#2A1240]"></div>
                </div>

                <Button
                  type="button"
                  variant="ghost"
                  onClick={handleGuestAccess}
                  className="w-full h-11 bg-[#12051F]/80 hover:bg-[#1F0838] text-[#C4B5FD] hover:text-white border border-[#2A1240] hover:border-[#A855F7]/50 rounded-2xl text-xs font-semibold transition-all flex items-center justify-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(0,0,0,0.5)]"
                >
                  <span>Explore Demo Workspace (Instant Access)</span>
                  <ArrowRight size={14} className="text-[#A855F7]" />
                </Button>

              </div>

              {/* Security & Compliance Assurance */}
              <div className="pt-6 mt-4 border-t border-[#2A1240]/60 text-center space-y-2">
                <div className="flex items-center justify-center gap-1.5 text-[11px] text-[#C4B5FD]/70">
                  <ShieldCheck size={14} className="text-emerald-400" />
                  <span>Enterprise OAuth 2.0 & Firebase Token Verification</span>
                </div>
                <p className="text-[10px] text-zinc-500">
                  By continuing, you agree to Rakshak's security protocols and workspace terms.
                </p>
              </div>

              {/* TOGGLE TAB LINK */}
              <div className="text-center pt-3">
                <p className="text-xs text-[#C4B5FD]/70">
                  {activeTab === 'login' ? (
                    <>
                      Don't have an account yet?{' '}
                      <button
                        type="button"
                        onClick={() => { setActiveTab('register'); setErrorMessage(null); }}
                        className="text-[#A855F7] hover:text-[#EC4899] font-bold transition-colors cursor-pointer underline ml-1"
                      >
                        Register with Google or GitHub
                      </button>
                    </>
                  ) : (
                    <>
                      Already have an account?{' '}
                      <button
                        type="button"
                        onClick={() => { setActiveTab('login'); setErrorMessage(null); }}
                        className="text-[#A855F7] hover:text-[#EC4899] font-bold transition-colors cursor-pointer underline ml-1"
                      >
                        Sign In
                      </button>
                    </>
                  )}
                </p>
              </div>

            </div>
          </motion.div>

          {/* RIGHT SIDE: GLOWING 3D SHIELD DISPLAY */}
          <motion.div 
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="lg:col-span-3 hidden lg:flex flex-col items-center justify-center order-3 relative py-6"
          >
            <div className="relative w-full max-w-[260px] h-[300px] flex items-center justify-center">
              
              <div className="absolute bottom-6 w-36 h-6 border border-[#EC4899]/50 rounded-full bg-[#12051F]/90 shadow-[0_0_25px_rgba(236,72,153,0.6)] flex items-center justify-center">
                <span className="text-[10px] font-black tracking-widest text-white drop-shadow-[0_0_8px_rgba(236,72,153,0.9)]">
                  RAKSHAK
                </span>
              </div>

              <motion.div 
                animate={{ y: [-6, 6, -6] }}
                transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                className="relative z-10 flex flex-col items-center"
              >
                <div className="relative flex items-center justify-center group">
                  <Shield className="w-28 h-28 text-[#A855F7] filter drop-shadow-[0_0_20px_rgba(168,85,247,0.8)]" />
                  <span className="absolute inset-0 flex items-center justify-center text-3xl font-black text-white drop-shadow-[0_0_12px_rgba(255,255,255,0.9)]">R</span>
                </div>

                <div className="w-28 h-1 bg-gradient-to-r from-transparent via-[#EC4899] to-transparent blur-[1px] mt-4 animate-pulse" />
              </motion.div>
            </div>
          </motion.div>

        </div>

        {/* BOTTOM FEATURE BAR */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="w-full max-w-5xl mx-auto mt-4 p-4 rounded-2xl bg-[#12051F]/60 border border-[#2A1240] backdrop-blur-md shadow-[0_0_30px_rgba(168,85,247,0.1)]"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            
            <div className="flex items-center gap-3 p-2">
              <div className="p-2.5 rounded-xl bg-[#A855F7]/10 text-[#A855F7] border border-[#A855F7]/30 shrink-0">
                <Sparkles size={18} />
              </div>
              <div>
                <h5 className="text-xs font-bold text-white">AI-Powered</h5>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-tight">Intelligent threat detection and risk analysis</p>
              </div>
            </div>

            <div className="flex items-center gap-3 p-2">
              <div className="p-2.5 rounded-xl bg-[#EC4899]/10 text-[#EC4899] border border-[#EC4899]/30 shrink-0">
                <InfinityIcon size={18} />
              </div>
              <div>
                <h5 className="text-xs font-bold text-white">DevSecOps Ready</h5>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-tight">Seamless integration in your CI/CD pipeline</p>
              </div>
            </div>

            <div className="flex items-center gap-3 p-2">
              <div className="p-2.5 rounded-xl bg-[#c026d3]/10 text-[#c026d3] border border-[#c026d3]/30 shrink-0">
                <Zap size={18} />
              </div>
              <div>
                <h5 className="text-xs font-bold text-white">Real-time Protection</h5>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-tight">Continuous monitoring and real-time alerts</p>
              </div>
            </div>

            <div className="flex items-center gap-3 p-2">
              <div className="p-2.5 rounded-xl bg-[#3b82f6]/10 text-[#3b82f6] border border-[#3b82f6]/30 shrink-0">
                <Lock size={18} />
              </div>
              <div>
                <h5 className="text-xs font-bold text-white">Secure & Private</h5>
                <p className="text-[11px] text-[#C4B5FD]/70 leading-tight">Your data is safe and encrypted</p>
              </div>
            </div>

          </div>
        </motion.div>

      </main>

      {/* FOOTER */}
      <footer className="w-full max-w-7xl mx-auto px-6 py-6 text-center z-10 text-xs text-[#C4B5FD]/60 flex flex-col sm:flex-row items-center justify-between gap-2 border-t border-[#2A1240]/40 mt-6">
        <p>&copy; 2025 Rakshak. All rights reserved.</p>
        <p className="flex items-center gap-1.5">
          <span>Built for a secure tomorrow</span>
          <span className="text-[#EC4899]">💜</span>
        </p>
      </footer>

    </div>
  );
}
