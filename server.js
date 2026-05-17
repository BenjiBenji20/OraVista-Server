const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// ---------------------------------------------------------
// DATABASE CONNECTION (XAMPP / MariaDB)
// ---------------------------------------------------------
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'oravista_db'
});

// ---------------------------------------------------------
// EMAIL TRANSPORTER SETUP
// ---------------------------------------------------------
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});

// ---------------------------------------------------------
// MULTER CONFIGURATION FOR UPLOADS
// ---------------------------------------------------------
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, 'profile_' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

const recordStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, 'record_' + Date.now() + path.extname(file.originalname));
    }
});
const uploadRecord = multer({ storage: recordStorage });


// ---------------------------------------------------------
// AUTHENTICATION ROUTES
// ---------------------------------------------------------

app.post('/api/signup', async (req, res) => {
    const { firstName, lastName, email, password, role, phone, dob, branch } = req.body;

    if (firstName.length > 20 || lastName.length > 20) {
        return res.status(400).json({ message: "Names must be 20 characters or less." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: "Invalid email format." });
    }

    try {
        const [existingUser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: "Email already registered." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const userRole = role || 'patient';
        const userBranch = branch || 'Main Branch';

        const query = 'INSERT INTO users (first_name, last_name, email, password, role, phone, dob, branch) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        await db.promise().query(query, [firstName, lastName, email, hashedPassword, userRole, phone || null, dob || null, userBranch]);

        res.status(201).json({ message: "Account created successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Database error." });
    }
});

// ---------------------------------------------------------
// ADMIN ROUTE: CREATE STAFF OR DENTIST
// ---------------------------------------------------------
app.post('/api/admin/create-user', async (req, res) => {
    const { firstName, lastName, email, password, role, branch, specialty, phone } = req.body;

    try {
        // Check if email exists
        const [existingUser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: "Email already registered." });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Insert into database including specialty and status
        const query = `
            INSERT INTO users (first_name, last_name, email, password, role, phone, branch, specialty, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Available')
        `;

        await db.promise().query(query, [firstName, lastName, email, hashedPassword, role, phone || null, branch, specialty || null]);

        res.status(201).json({ message: "Staff/Dentist account created successfully!" });
    } catch (err) {
        console.error("Admin Creation Error:", err);
        res.status(500).json({ message: "Database error." });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Fetch User
        const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);

        // Log for debugging: See if the email even exists in the DB
        console.log(`Login attempt for: ${email}`);

        if (users.length === 0) {
            console.log("❌ Error: Email not found in database.");
            return res.status(401).json({ message: "Invalid email or password." });
        }

        const user = users[0];

        // 2. Handle Plain-Text Seed Data (ID 81-86)
        // If the DB password isn't a valid bcrypt hash (starts with $2b$), 
        // we do a direct string comparison for your dummy data.
        let isMatch = false;
        if (!user.password.startsWith('$2b$')) {
            console.log("⚠️ Warning: Non-bcrypt password detected in DB. Using direct match.");
            isMatch = (password === user.password);
        } else {
            // 3. Normal Bcrypt Comparison
            isMatch = await bcrypt.compare(password, user.password);
        }

        if (!isMatch) {
            console.log("❌ Error: Password mismatch.");
            return res.status(401).json({ message: "Invalid email or password." });
        }

        console.log("✅ Success: Login verified for", user.role);

        // 4. Successful Response
        res.status(200).json({
            message: "Login successful",
            user: {
                id: user.id,
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                role: user.role,
                branch: user.branch || "",
                profile_picture: user.profile_picture || ""
            }
        });

    } catch (err) {
        console.error("🔥 Server Error:", err);
        res.status(500).json({ message: "Server error." });
    }
});

app.post('/api/check-email', async (req, res) => {
    const { email } = req.body;
    try {
        const [users] = await db.promise().query('SELECT first_name FROM users WHERE email = ?', [email]);
        if (users.length > 0) res.status(200).json({ firstName: users[0].first_name });
        else res.status(404).json({ message: "Email not found" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

app.put('/api/reset-password-by-email', async (req, res) => {
    const { email, newPassword } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await db.promise().query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
        res.status(200).json({ message: "Password updated successfully!" });
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
});

// ---------------------------------------------------------
// OTP / DYNAMIC EMAIL ROUTE
// ---------------------------------------------------------
app.post('/api/send-otp', async (req, res) => {
    const { email, action } = req.body;

    try {
        const [users] = await db.promise().query('SELECT first_name FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ message: "Email not found in our system." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        let emailSubject = '';
        let emailBodyContext = '';

        if (action === 'change_password') {
            emailSubject = 'OraVista - Change Password Request';
            emailBodyContext = 'This is a change password request. You have initiated a request to change your current password from within your account settings. To authorize and confirm this security change, please use the code below.';
        } else if (action === 'login') {
            emailSubject = 'OraVista - Login Verification';
            emailBodyContext = 'This is a login verification. A new sign-in attempt was detected for your OraVista account. To verify your identity and complete the login process, please enter the security code below.';
        } else if (action === 'forgot_password') {
            emailSubject = 'OraVista - Forgot Password Request';
            emailBodyContext = 'This is a forgot password request. We received a request to recover your OraVista account because you forgot your password. Please use the verification code below to gain access and set a new password.';
        } else {
            emailSubject = 'OraVista - Forgot Password Request';
            emailBodyContext = 'This is a forgot password request. We received a request to reset the password for your account. Please use the verification code below to proceed.';
        }

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: emailSubject,
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; color: #001166;">
                    <h2>King Epres Dental Clinic</h2>
                    <p>Hello ${users[0].first_name},</p>
                    <p>${emailBodyContext}</p>
                    <h1 style="background: #f4f4f4; padding: 10px; display: inline-block; letter-spacing: 5px;">${otp}</h1>
                    <p>This code will expire shortly.</p>
                    <p>If you did not initiate this request, please secure your account immediately and ignore this email.</p>
                </div>
            `
        };

        // Check if the system is running in development mode
        if (process.env.ENVIRONMENT === 'dev') {
            console.log(`\n[DEV MODE] Bypass active. OTP for ${email} is: ${otp}\n`);
        } else {
            // Live email delivery only runs in production
            await transporter.sendMail(mailOptions);
        }

        res.status(200).json({ message: "OTP sent successfully!", generatedOtp: otp });

    } catch (err) {
        console.error("Email Error:", err);
        res.status(500).json({ message: "Failed to send email." });
    }
});

// ---------------------------------------------------------
// PROFILE & SETTINGS ROUTES
// ---------------------------------------------------------

app.put('/api/update-profile', async (req, res) => {
    const {
        id, firstName, lastName, email, sex, dob, age, phone,
        occupation, blood_type, allergies, insurance, policy_number
    } = req.body;

    // Convert empty strings to null for database columns that expect numbers or dates
    const safeAge = age === '' ? null : age;
    const safeDob = dob === '' ? null : dob;

    try {
        const query = `UPDATE users SET first_name = ?, last_name = ?, email = ?, sex = ?, dob = ?, age = ?, phone = ?, occupation = ?, blood_type = ?, allergies = ?, insurance = ?, policy_number = ? WHERE id = ?`;

        // Pass safeAge and safeDob to the database query
        await db.promise().query(query, [firstName, lastName, email, sex, safeDob, safeAge, phone, occupation, blood_type, allergies, insurance, policy_number, id]);

        res.status(200).json({ message: "Profile updated successfully!" });
    } catch (err) {
        console.error("Database Update Error:", err);
        res.status(500).json({ message: "Failed to update profile." });
    }
});

app.put('/api/update-password', async (req, res) => {
    const { id, oldPassword, newPassword } = req.body;
    try {
        const [users] = await db.promise().query('SELECT password FROM users WHERE id = ?', [id]);
        const isMatch = await bcrypt.compare(oldPassword, users[0].password);
        if (!isMatch) return res.status(401).json({ message: "Incorrect old password." });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await db.promise().query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, id]);
        res.status(200).json({ message: "Password updated successfully!" });
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
});

app.post('/api/upload-profile-picture', upload.single('profileImage'), async (req, res) => {
    const { userId } = req.body;

    if (!req.file) {
        return res.status(400).json({ message: "No image file provided." });
    }

    const imagePath = 'uploads/' + req.file.filename;

    try {
        await db.promise().query('UPDATE users SET profile_picture = ? WHERE id = ?', [imagePath, userId]);
        res.status(200).json({
            message: "Profile picture updated successfully!",
            imagePath: imagePath
        });
    } catch (err) {
        console.error("Upload DB Error:", err);
        res.status(500).json({ message: "Failed to save picture path to database." });
    }
});

// ---------------------------------------------------------
// PATIENT RECORDS ROUTES
// ---------------------------------------------------------

app.post('/api/upload-record', uploadRecord.single('recordFile'), async (req, res) => {
    const { userId, fileName } = req.body;

    if (!req.file) {
        return res.status(400).json({ message: "No file provided." });
    }

    const filePath = 'uploads/' + req.file.filename;
    const finalFileName = fileName || req.file.originalname;

    try {
        const query = 'INSERT INTO patient_records (user_id, file_name, file_path) VALUES (?, ?, ?)';
        await db.promise().query(query, [userId, finalFileName, filePath]);

        res.status(201).json({
            message: "Record uploaded successfully!",
            record: { file_name: finalFileName, file_path: filePath }
        });
    } catch (err) {
        console.error("Record Upload DB Error:", err);
        res.status(500).json({ message: "Failed to save record to database." });
    }
});

app.get('/api/patient-records/:userId', async (req, res) => {
    try {
        const [records] = await db.promise().query(
            'SELECT id, file_name, file_path, upload_date FROM patient_records WHERE user_id = ? ORDER BY upload_date DESC',
            [req.params.userId]
        );
        res.status(200).json(records);
    } catch (err) {
        console.error("Fetch Records Error:", err);
        res.status(500).json({ message: "Failed to fetch patient records." });
    }
});


// ---------------------------------------------------------
// APPOINTMENT ROUTES
// ---------------------------------------------------------

app.post('/api/book-appointment', async (req, res) => {
    const { user_id, service_type, dentist_name, appointment_date, appointment_time, amount, branch } = req.body;

    try {
        const randomString = crypto.randomBytes(3).toString('hex').toUpperCase();
        const booking_ref = `OV - ${randomString}`;

        const amountToSave = amount || 0.00;
        const branchToSave = branch || "Main Branch";

        const query = `
            INSERT INTO appointments 
            (user_id, booking_ref, service_type, dentist_name, appointment_date, appointment_time, status, amount, branch) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        await db.promise().query(query, [user_id, booking_ref, service_type, dentist_name, appointment_date, appointment_time, 'Pending', amountToSave, branchToSave]);

        res.status(201).json({
            message: "Appointment booked successfully!",
            booking_ref: booking_ref
        });
    } catch (err) {
        console.error("Booking Error:", err);
        res.status(500).json({ message: "Failed to book appointment." });
    }
});

app.get('/api/user-appointments/:userId', async (req, res) => {
    try {
        const [results] = await db.promise().query('SELECT * FROM appointments WHERE user_id = ? ORDER BY appointment_date DESC', [req.params.userId]);
        res.status(200).json(results);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch appointments." });
    }
});

app.put('/api/update-appointment-status', async (req, res) => {
    const { appointment_id, status } = req.body;
    try {
        await db.promise().query('UPDATE appointments SET status = ? WHERE id = ?', [status, appointment_id]);
        res.status(200).json({ message: `Appointment marked as ${status}.` });
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
});

app.get('/api/appointments/check-availability', async (req, res) => {
    const { date, dentist } = req.query;
    try {
        const [results] = await db.promise().query('SELECT appointment_time, service_type FROM appointments WHERE appointment_date = ? AND dentist_name = ?', [date, dentist]);
        const bookedData = results.map(row => ({ time: row.appointment_time, service: row.service_type }));
        res.status(200).json(bookedData);
    } catch (err) {
        res.status(500).json({ message: "Error checking availability" });
    }
});

// ---------------------------------------------------------
// PORTAL DASHBOARD & LISTS (ADMIN / STAFF / DENTIST)
// ---------------------------------------------------------

app.get('/api/dashboard/stats', async (req, res) => {
    try {
        const promiseDb = db.promise();

        const [todayRows] = await promiseDb.query("SELECT COUNT(*) as count FROM appointments WHERE DATE(appointment_date) = CURDATE()");
        const [totalDentistsRows] = await promiseDb.query("SELECT COUNT(*) as count FROM users WHERE role = 'dentist'");
        const [busyDentistsRows] = await promiseDb.query(`SELECT COUNT(DISTINCT dentist_name) as count FROM appointments WHERE DATE(appointment_date) = CURDATE() AND status = 'Confirmed'`);
        const [monthPatientsRows] = await promiseDb.query(`SELECT COUNT(DISTINCT user_id) as count FROM appointments WHERE MONTH(appointment_date) = MONTH(CURDATE()) AND YEAR(appointment_date) = YEAR(CURDATE())`);

        const [scheduleRows] = await promiseDb.query(`
            SELECT a.id, a.booking_ref, a.appointment_time, a.appointment_date, a.dentist_name, a.status, a.service_type,
            CONCAT(u.first_name, ' ', u.last_name) as patient_name
            FROM appointments a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.appointment_date ASC, a.appointment_time ASC
        `);

        res.json({
            todayCount: todayRows[0].count,
            totalDentists: totalDentistsRows[0].count,
            availableDentists: totalDentistsRows[0].count - busyDentistsRows[0].count,
            monthPatients: monthPatientsRows[0].count,
            schedule: scheduleRows.map(row => ({
                id: row.id,
                booking_ref: row.booking_ref,
                time: row.appointment_time,
                date: row.appointment_date,
                dentist: row.dentist_name,
                patientName: row.patient_name || "Guest",
                status: row.status,
                serviceType: row.service_type
            }))
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to fetch stats." });
    }
});

app.get('/api/dashboard/branch-earnings', async (req, res) => {
    try {
        const query = `
            SELECT branch, SUM(amount) as total_earnings 
            FROM appointments 
            WHERE status != 'Cancelled'
            GROUP BY branch
        `;
        const [results] = await db.promise().query(query);

        const earningsObj = {};
        results.forEach(row => {
            earningsObj[row.branch || "Unknown Branch"] = row.total_earnings || 0;
        });

        res.status(200).json(earningsObj);
    } catch (err) {
        console.error("Earnings API Error:", err);
        res.status(500).json({ message: "Failed to fetch earnings." });
    }
});

app.get('/api/patients', async (req, res) => {
    try {
        const query = `
            SELECT id, CONCAT(first_name, ' ', last_name) AS name, email, age, phone AS contact, 
            blood_type, allergies, insurance, policy_number, branch,
            (SELECT MAX(appointment_date) FROM appointments WHERE appointments.user_id = users.id) AS lastVisit 
            FROM users 
            WHERE role = 'patient' 
            ORDER BY last_name ASC
        `;
        const [patients] = await db.promise().query(query);
        res.status(200).json(patients);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch patients list." });
    }
});

app.get('/api/dentists', async (req, res) => {
    try {
        const query = `
            SELECT 
                u.id, u.first_name, u.last_name, u.specialty, u.status AS manual_status, u.branch,
                (SELECT COUNT(*) FROM appointments a WHERE a.dentist_name LIKE CONCAT('%', u.last_name, '%')) AS patient_count,
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM appointments a 
                        WHERE a.dentist_name LIKE CONCAT('%', u.last_name, '%') 
                        AND DATE(a.appointment_date) = CURDATE()
                        AND a.status = 'Confirmed'
                    ) THEN 'Busy'
                    ELSE IFNULL(u.status, 'Available')
                END AS status
            FROM users u
            WHERE u.role = 'dentist'
            ORDER BY u.last_name ASC
        `;
        const [dentists] = await db.promise().query(query);
        res.status(200).json(dentists);
    } catch (err) {
        console.error("Fetch Dentists Error:", err);
        res.status(500).json({ message: "Failed to fetch dentists list." });
    }
});

app.get('/api/dentist-profile/:id', async (req, res) => {
    const dentistId = req.params.id;
    try {
        const promiseDb = db.promise();

        const [dentistRows] = await promiseDb.query(
            `SELECT id, first_name, last_name, email, specialty, status, phone, branch,
            (SELECT COUNT(DISTINCT user_id) FROM appointments WHERE dentist_name LIKE CONCAT('%', last_name, '%')) as patient_count,
            (SELECT COUNT(*) FROM appointments WHERE dentist_name LIKE CONCAT('%', last_name, '%') AND status = 'Completed') as procedures_count
            FROM users WHERE id = ? AND role = 'dentist'`,
            [dentistId]
        );

        if (dentistRows.length === 0) return res.status(404).json({ message: "Dentist not found" });

        const dentist = dentistRows[0];

        const [patientRows] = await promiseDb.query(`
            SELECT DISTINCT u.id, CONCAT(u.first_name, ' ', u.last_name) as name, 
            a.service_type as case_type, 
            (SELECT MAX(appointment_date) FROM appointments WHERE user_id = u.id) as last_visit
            FROM users u
            JOIN appointments a ON u.id = a.user_id
            WHERE a.dentist_name LIKE CONCAT('%', ?, '%')
            LIMIT 5`,
            [dentist.last_name]
        );

        const [scheduleRows] = await promiseDb.query(`
            SELECT a.appointment_time, CONCAT(u.first_name, ' ', u.last_name) as patient_name, a.service_type as type
            FROM appointments a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.dentist_name LIKE CONCAT('%', ?, '%') 
            AND DATE(a.appointment_date) = CURDATE()
            ORDER BY a.appointment_time ASC`,
            [dentist.last_name]
        );

        res.json({
            profile: dentist,
            patients: patientRows,
            schedule: scheduleRows.map(row => ({
                time: row.appointment_time,
                patientName: row.patient_name || "Guest",
                type: row.type
            }))
        });
    } catch (err) {
        console.error("Dentist Profile API Error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ---------------------------------------------------------
// AI DIAGNOSTICS ROUTES
// ---------------------------------------------------------

app.post('/api/save-diagnosis', async (req, res) => {
    const { patient_id, clinical_notes, ai_findings } = req.body;

    const findingsJson = JSON.stringify(ai_findings);

    try {
        const query = `
            INSERT INTO ai_diagnostics (patient_id, clinical_notes, ai_findings) 
            VALUES (?, ?, ?)
        `;

        await db.promise().query(query, [patient_id, clinical_notes, findingsJson]);

        res.status(201).json({
            status: "success",
            message: "Diagnostic record saved successfully!"
        });
    } catch (err) {
        console.error("Database Error:", err);
        res.status(500).json({
            status: "error",
            message: "Failed to save diagnosis"
        });
    }
});

// ---------------------------------------------------------
// START SERVER
// ---------------------------------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`OraVista Backend running on http://localhost:${PORT}`);
});