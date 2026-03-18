const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'https://lefos5.github.io');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action } = req.query;

  // ─── Helper: session ID'yi cookie VEYA query param'dan oku ───
  function getSessionId(req) {
    const cookie = req.headers.cookie || '';
    const match = cookie.match(/akademix_session=([^;]+)/);
    return (match && match[1]) || req.query.session || null;
  }

  // ─── action=login → Google OAuth başlat ─────────────────────
  if (action === 'login') {
    const params = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: `${process.env.BACKEND_URL || 'https://akademix-backend.vercel.app'}/api/callback`,
      response_type: 'code',
      scope: [
        'openid',
        'email',
        'profile',
        'https://www.googleapis.com/auth/classroom.courses.readonly',
        'https://www.googleapis.com/auth/classroom.coursework.me.readonly',
        'https://www.googleapis.com/auth/classroom.announcements.readonly',
      ].join(' '),
      access_type: 'offline',
      prompt: 'consent',
    });
    return res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  }

  // ─── action=me → oturum bilgisini döndür ────────────────────
  if (action === 'me') {
    const sessionId = getSessionId(req);

    if (!sessionId) {
      return res.status(401).json({ error: 'No session' });
    }

    const { data: session, error } = await supabase
      .from('sessions')
      .select('*')
      .eq('id', sessionId)
      .single();

    if (error || !session) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    // Oturum süresi dolmuş mu?
    if (session.expires_at && new Date(session.expires_at) < new Date()) {
      await supabase.from('sessions').delete().eq('id', sessionId);
      return res.status(401).json({ error: 'Session expired' });
    }

    return res.status(200).json({
      user: session.user_data,
      accessToken: session.access_token,
    });
  }

  // ─── action=logout → session'ı sil ──────────────────────────
  if (action === 'logout') {
    const sessionId = getSessionId(req);

    if (sessionId) {
      await supabase.from('sessions').delete().eq('id', sessionId);
    }

    // Cookie'yi temizle
    res.setHeader('Set-Cookie', 'akademix_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None');

    return res.status(200).json({ success: true });
  }

  return res.status(400).json({ error: 'Unknown action' });
};
