// auth.js — fungsi sanitasi, validasi, autentikasi demo, sesi dan reset password (client-side)
// Pastikan file ini sudah ada; file berikut melengkapi/menjaga kompatibilitas.

(function(window){
    const ADMIN_CRED = { email: 'admin@gmail.com', password: 'AdminAja' };

    function sanitize(str){
        if (!str && str !== '') return '';
        return String(str).trim().replace(/[<>&"]/g, function(c){
            return ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'})[c];
        });
    }

    function validateEmail(email){
        email = sanitize(email);
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;
        return re.test(email);
    }

    function validatePassword(pwd){
        pwd = String(pwd || '');
        return pwd.length >= 6;
    }

    function generateToken(){
        return 't_' + Math.random().toString(36).slice(2) + Date.now().toString(36);
    }

    // authLogin: jika tidak diberikan rawRole, otomatis deteksi admin bila kredensial cocok
    function authLogin(rawEmail, rawPassword, rawRole){
        const email = sanitize(rawEmail);
        const password = sanitize(rawPassword);
        const explicitRole = (rawRole !== undefined && rawRole !== null) ? sanitize(rawRole) : null;

        if (!validateEmail(email)) return { ok:false, error: 'Email tidak valid.' };
        if (!validatePassword(password)) return { ok:false, error: 'Kata sandi minimal 6 karakter.' };

        let role = 'user';
        let isAdmin = false;
        const credMatchAdmin = (email.toLowerCase() === ADMIN_CRED.email && password === ADMIN_CRED.password);

        if (explicitRole) {
            if (!['user','guest','admin'].includes(explicitRole)) {
                return { ok:false, error: 'Peran tidak dikenali.' };
            }
            role = explicitRole;
            if (explicitRole === 'admin') {
                if (!credMatchAdmin) return { ok:false, error: 'Kredensial admin salah.' };
                isAdmin = true;
            }
        } else {
            if (credMatchAdmin) {
                role = 'admin';
                isAdmin = true;
            } else {
                role = 'user';
            }
        }

        const session = {
            email,
            role,
            isAdmin,
            token: generateToken(),
            issuedAt: Date.now()
        };
        try {
            localStorage.setItem('perpusri_user', JSON.stringify(session));
        } catch (e) {
            return { ok:false, error: 'Gagal menyimpan sesi. Pastikan localStorage tersedia.' };
        }

        return { ok:true, session };
    }

    function isAuthenticated(){
        try {
            const s = JSON.parse(localStorage.getItem('perpusri_user') || 'null');
            return s && s.token;
        } catch(e){ return false; }
    }

    function getSession(){
        try { return JSON.parse(localStorage.getItem('perpusri_user') || 'null'); } catch(e){ return null; }
    }

    function logout(){
        localStorage.removeItem('perpusri_user');
    }

    function sendPasswordReset(rawEmail){
        const email = sanitize(rawEmail);
        return new Promise((resolve) => {
            if (!validateEmail(email)) {
                resolve({ ok:false, error: 'Masukkan email yang valid.' });
                return;
            }
            setTimeout(()=> resolve({ ok:true }), 800);
        });
    }

    window.authLogin = authLogin;
    window.isAuthenticated = isAuthenticated;
    window.getSession = getSession;
    window.logout = logout;
    window.sendPasswordReset = sendPasswordReset;

})(window);