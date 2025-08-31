// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// ===== Schemas =====
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, lowercase: true },
    password: String,
    role: { type: String, default: 'technician' },
    createdAt: { type: Date, default: Date.now }
});

const JobSchema = new mongoose.Schema({
    jobId: String,
    customerName: String,
    customerPhone: String,
    customerEmail: String,
    deviceType: String,
    deviceBrand: String,
    deviceModel: String,
    problemDescription: String,
    status: { type: String, enum: ['Pending', 'In Progress', 'Completed', 'Cancelled'], default: 'Pending' },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    estimatedCost: Number,
    actualCost: Number,
    parts: Array,
    notes: Array,
    createdAt: { type: Date, default: Date.now }
});

JobSchema.virtual('whatsappLink').get(function() {
    if (this.customerPhone) {
        const phone = this.customerPhone.replace(/\D/g, '');
        return `https://wa.me/${phone}`;
    }
    return null;
});

JobSchema.set('toJSON', { virtuals: true });
JobSchema.set('toObject', { virtuals: true });

const CustomerSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    address: String,
    createdAt: { type: Date, default: Date.now }
});

const InventorySchema = new mongoose.Schema({
    name: String,
    partNumber: String,
    stock: Number,
    cost: Number,
    minStock: { type: Number, default: 5 },
    category: String,
    supplier: String,
    createdAt: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
    title: String,
    message: String,
    type: { type: String, enum: ['info', 'success', 'warning', 'error'], default: 'info' },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// ===== Models =====
const User = mongoose.model('User', UserSchema);
const Job = mongoose.model('Job', JobSchema);
const Customer = mongoose.model('Customer', CustomerSchema);
const Inventory = mongoose.model('Inventory', InventorySchema);
const Notification = mongoose.model('Notification', NotificationSchema);

const SettingSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: mongoose.Schema.Types.Mixed
});
const Setting = mongoose.model('Setting', SettingSchema);

// ===== MongoDB Atlas Connection =====
mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
      console.log("✅ MongoDB Connected to Atlas");

      try {
        // Initialize backup scheduler
        await initializeScheduler();
      } catch (err) {
          console.error("🚨 Failed to initialize backup scheduler:", err);
      }
      // --- Default Admin Seeder ---
      const adminEmail = "admin@pcgarage.com";
      const existingAdmin = await User.findOne({ email: adminEmail });

      if (!existingAdmin) {
          const hashedPassword = await bcrypt.hash("password123", 10);
          const admin = new User({
              name: "Admin",
              email: adminEmail,
              password: hashedPassword,
              role: "admin"
          });
          await admin.save();
          console.log("👑 Default Admin Created: admin@pcgarage.com / password123");
      }
  })
  .catch(err => console.error("❌ MongoDB Atlas Connection Error:", err));


// ===== Auth Middleware =====
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Invalid token" });
        req.user = decoded;
        next();
    });
};

// ===== Auth Routes =====
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        const normalizedEmail = email.toLowerCase();
        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) return res.status(400).json({ message: "Email already exists" });

        const hashed = await bcrypt.hash(password, 10);
        const user = new User({ name, email: normalizedEmail, password: hashed, role });
        await user.save();

        res.json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Registration Error:", err);
        res.status(500).json({ message: "Error registering user", error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const email = req.body.email.toLowerCase();
        const { password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "Invalid email or password" });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ message: "Invalid email or password" });

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
        const { password: pwd, ...userWithoutPassword } = user.toObject();

        res.json({ user: userWithoutPassword, token });
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ message: "Error logging in", error: err.message });
    }
});

// ===== Jobs API =====
app.get('/api/jobs', authMiddleware, async (req, res) => {
    try {
        const jobs = await Job.find().populate('assignedTo', 'name');
        res.json(jobs);
    } catch (err) {
        console.error("Get Jobs Error:", err);
        res.status(500).json({ message: "Error fetching jobs", error: err.message });
    }
});

app.post('/api/jobs', authMiddleware, async (req, res) => {
    try {
        const data = req.body;
        if (!data.assignedTo || data.assignedTo === "") data.assignedTo = null;
        const job = new Job(data);
        await job.save();
        await createNotification(
            'New Job Created',
            `Job ${job.jobId} for ${job.customerName} has been created.`,
            'success'
        );
        res.status(201).json(job);
    } catch (err) {
        console.error("Create Job Error:", err);
        res.status(400).json({ message: "Error creating job", error: err.message });
    }
});

app.put('/api/jobs/:id', authMiddleware, async (req, res) => {
    try {
        const jobBeforeUpdate = await Job.findById(req.params.id).lean();
        if (!jobBeforeUpdate) {
            return res.status(404).json({ message: "Job not found" });
        }

        const updatedJob = await Job.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updatedJob) return res.status(404).json({ message: "Job not found" });

        const oldStatus = jobBeforeUpdate.status;
        const newStatus = updatedJob.status;

        if (oldStatus !== newStatus) {
            await createNotification(
                'Job Status Updated',
                `Job ${updatedJob.jobId} for ${updatedJob.customerName} is now "${updatedJob.status}".`,
                'info'
            );
        }

        // Adjust inventory based on status change and parts list change
        const partChanges = new Map();
        const oldParts = jobBeforeUpdate.parts || [];
        const newParts = updatedJob.parts || [];

        // Status changed TO 'Completed'
        if (newStatus === 'Completed' && oldStatus !== 'Completed') {
            for (const part of newParts) {
                partChanges.set(part._id.toString(), (partChanges.get(part._id.toString()) || 0) - part.quantity);
            }
        } 
        // Status changed FROM 'Completed'
        else if (newStatus !== 'Completed' && oldStatus === 'Completed') {
            for (const part of oldParts) {
                partChanges.set(part._id.toString(), (partChanges.get(part._id.toString()) || 0) + part.quantity);
            }
        } 
        // Status REMAINS 'Completed', but parts list might have changed
        else if (newStatus === 'Completed' && oldStatus === 'Completed') {
            oldParts.forEach(p => partChanges.set(p._id.toString(), (partChanges.get(p._id.toString()) || 0) + p.quantity));
            newParts.forEach(p => partChanges.set(p._id.toString(), (partChanges.get(p._id.toString()) || 0) - p.quantity));
        }

        const bulkOps = [];
        for (const [partId, quantityChange] of partChanges.entries()) {
            if (quantityChange !== 0) {
                bulkOps.push({
                    updateOne: { filter: { _id: partId }, update: { $inc: { stock: quantityChange } } }
                });
            }
        }

        if (bulkOps.length > 0) {
            await Inventory.bulkWrite(bulkOps);
        }

        res.json(updatedJob);
    } catch (err) {
        console.error("Update Job Error:", err);
        res.status(500).json({ message: "Error updating job", error: err.message });
    }
});

app.delete('/api/jobs/:id', authMiddleware, async (req, res) => {
    try {
        const deletedJob = await Job.findByIdAndDelete(req.params.id);
        if (!deletedJob) return res.status(404).json({ message: "Job not found" });
        res.json({ message: "Job deleted successfully" });
    } catch (err) {
        console.error("Delete Job Error:", err);
        res.status(500).json({ message: "Error deleting job", error: err.message });
    }
});

app.post('/api/jobs/:id/complete', authMiddleware, async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);
        if (!job) return res.status(404).json({ message: "Job not found" });

        if (job.status !== 'Completed') {
            // Deduct used parts from inventory
            if (job.parts && job.parts.length > 0) {
                const bulkOps = job.parts.map(part => ({
                    updateOne: {
                        filter: { _id: part._id },
                        update: { $inc: { stock: -part.quantity } }
                    }
                }));
                await Inventory.bulkWrite(bulkOps);
            }

            job.status = 'Completed';
            const updatedJob = await job.save();

            await createNotification(
                'Job Completed',
                `Job ${updatedJob.jobId} for ${updatedJob.customerName} has been marked as completed.`,
                'success'
            );
            res.json(updatedJob);
        } else {
            res.json(job); // Already completed, just return it.
        }
    } catch (err) {
        console.error("Complete Job Error:", err);
        res.status(500).json({ message: "Error completing job", error: err.message });
    }
});

// ===== Customers API =====
app.get('/api/customers', authMiddleware, async (req, res) => {
    try {
        res.json(await Customer.find());
    } catch (err) {
        console.error("Get Customers Error:", err);
        res.status(500).json({ message: "Error fetching customers", error: err.message });
    }
});
app.post('/api/customers', authMiddleware, async (req, res) => {
    try {
        const customer = new Customer(req.body);
        await customer.save();
        res.status(201).json(customer);
    } catch (err) {
        console.error("Create Customer Error:", err);
        res.status(400).json({ message: "Error creating customer", error: err.message });
    }
});
app.put('/api/customers/:id', authMiddleware, async (req, res) => {
    try {
        const customer = await Customer.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!customer) return res.status(404).json({ message: "Customer not found" });
        res.json(customer);
    } catch (err) {
        console.error("Update Customer Error:", err);
        res.status(500).json({ message: "Error updating customer", error: err.message });
    }
});
app.delete('/api/customers/:id', authMiddleware, async (req, res) => {
    try {
        const customer = await Customer.findByIdAndDelete(req.params.id);
        if (!customer) return res.status(404).json({ message: "Customer not found" });
        res.json({ message: "Customer deleted successfully" });
    } catch (err) {
        console.error("Delete Customer Error:", err);
        res.status(500).json({ message: "Error deleting customer", error: err.message });
    }
});

// ===== Inventory API =====
app.get('/api/inventory', authMiddleware, async (req, res) => {
    try {
        res.json(await Inventory.find());
    } catch (err) {
        console.error("Get Inventory Error:", err);
        res.status(500).json({ message: "Error fetching inventory", error: err.message });
    }
});
app.post('/api/inventory', authMiddleware, async (req, res) => {
    try {
        const item = new Inventory(req.body);
        await item.save();
        res.status(201).json(item);
    } catch (err) {
        console.error("Create Inventory Error:", err);
        res.status(400).json({ message: "Error creating inventory item", error: err.message });
    }
});
app.put('/api/inventory/:id', authMiddleware, async (req, res) => {
    try {
        const item = await Inventory.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!item) return res.status(404).json({ message: "Inventory item not found" });
        res.json(item);
    } catch (err) {
        console.error("Update Inventory Error:", err);
        res.status(500).json({ message: "Error updating inventory item", error: err.message });
    }
});
app.delete('/api/inventory/:id', authMiddleware, async (req, res) => {
    try {
        const item = await Inventory.findByIdAndDelete(req.params.id);
        if (!item) return res.status(404).json({ message: "Inventory item not found" });
        res.json({ message: "Inventory item deleted successfully" });
    } catch (err) {
        console.error("Delete Inventory Error:", err);
        res.status(500).json({ message: "Error deleting inventory item", error: err.message });
    }
});

// ===== Users API =====
app.get('/api/users', authMiddleware, async (req, res) => {
    try {
        res.json(await User.find().select('-password'));
    } catch (err) {
        console.error("Get Users Error:", err);
        res.status(500).json({ message: "Error fetching users", error: err.message });
    }
});
app.put('/api/users/:id', authMiddleware, async (req, res) => {
    try {
        // Make sure password is not updated this way
        if (req.body.password) {
            delete req.body.password;
        }
        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select('-password');
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
    } catch (err) {
        console.error("Update User Error:", err);
        res.status(500).json({ message: "Error updating user", error: err.message });
    }
});
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json({ message: "User deleted successfully" });
    } catch (err) {
        console.error("Delete User Error:", err);
        res.status(500).json({ message: "Error deleting user", error: err.message });
    }
});

// ===== Notifications API =====
app.get('/api/notifications', authMiddleware, async (req, res) => {
    try {
        res.json(await Notification.find().sort({ createdAt: -1 }));
    } catch (err) {
        console.error("Get Notifications Error:", err);
        res.status(500).json({ message: "Error fetching notifications", error: err.message });
    }
});

// ===== Dashboard Stats =====
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
    try {
        const totalJobs = await Job.countDocuments();
        const pendingJobs = await Job.countDocuments({ status: 'Pending' });
        const completedJobs = await Job.countDocuments({ status: 'Completed' });
        const totalRevenue = await Job.aggregate([{ $group: { _id: null, total: { $sum: "$actualCost" } } }]);
        res.json({
            totalJobs,
            pendingJobs,
            completedJobs,
            totalRevenue: totalRevenue[0]?.total || 0
        });
    } catch (err) {
        console.error("Get Dashboard Stats Error:", err);
        res.status(500).json({ message: "Error fetching dashboard stats", error: err.message });
    }
});

// ===== Chart Data =====
app.get('/api/jobs/chart/status', authMiddleware, async (req, res) => {
    try {
        const data = await Job.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]);
        res.json(data);
    } catch (err) {
        console.error("Get Chart Status Error:", err);
        res.status(500).json({ message: "Error fetching chart data", error: err.message });
    }
});

app.get('/api/jobs/chart/revenue', authMiddleware, async (req, res) => {
    try {
        const data = await Job.aggregate([
            { $match: { status: 'Completed', actualCost: { $gt: 0 } } },
            { $group: { _id: { year: { $year: "$createdAt" }, month: { $month: "$createdAt" } }, revenue: { $sum: "$actualCost" } } },
            { $sort: { "_id.year": 1, "_id.month": 1 } }
        ]);
        res.json(data);
    } catch (err) {
        console.error("Get Chart Revenue Error:", err);
        res.status(500).json({ message: "Error fetching chart data", error: err.message });
    }
});

// ===== Backup & Restore API =====
const upload = multer({ dest: 'uploads/' });

// Function to get backup settings from DB
async function getBackupSettings() {
    const autoBackup = await Setting.findOne({ key: 'autoBackup' });
    const backupPathSetting = await Setting.findOne({ key: 'backupPath' });
    let backupPath = backupPathSetting ? backupPathSetting.value : '';

    // If no backup path is configured, default to a 'backups' directory in the project root.
    if (!backupPath) {
        backupPath = path.join(__dirname, 'backups');
    }

    return {
        autoBackup: autoBackup ? autoBackup.value : false,
        backupPath: backupPath
    };
}

// Function to perform a backup
const performBackup = async () => {
    const { backupPath } = await getBackupSettings();
    if (!backupPath) {
        console.error('Backup failed: Backup path not configured.');
        return { success: false, message: 'Backup path not configured.' };
    }

    if (!fs.existsSync(backupPath)) {
        try {
            fs.mkdirSync(backupPath, { recursive: true });
        } catch (error) {
            console.error(`Backup failed: Could not create directory ${backupPath}`, error);
            return { success: false, message: `Could not create directory ${backupPath}` };
        }
    }

    const dbName = mongoose.connection.name;
    const date = new Date().toISOString().replace(/:/g, '-');
    const archivePath = path.join(backupPath, `backup-${dbName}-${date}.gz`);
    const command = `mongodump --uri="${process.env.MONGO_URI}" --archive="${archivePath}" --gzip`;

    return new Promise((resolve) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Backup Error: ${error.message}`);
                console.error(`stderr: ${stderr}`);
                resolve({ success: false, message: `Backup failed: ${error.message}` });
                return;
            }
            console.log(`Backup successful: ${archivePath}`);
            resolve({ success: true, message: `Backup successful. Saved to ${archivePath}` });
        });
    });
};

// Schedule cron job
let backupJob;
const scheduleBackup = async () => {
    if (backupJob) {
        backupJob.stop();
    }
    const { autoBackup } = await getBackupSettings();
    if (autoBackup) {
        // Schedule to run at 2 AM every day
        backupJob = cron.schedule('0 2 * * *', () => {
            console.log('Running scheduled daily backup...');
            performBackup().catch(err => {
                console.error('Scheduled backup failed:', err);
            });
        });
        console.log('Scheduled daily backup is enabled.');
    } else {
        console.log('Scheduled daily backup is disabled.');
    }
};

const initializeScheduler = async () => {
    await scheduleBackup();
};

app.get('/api/settings/backup', authMiddleware, async (req, res) => {
    try {
        const settings = await getBackupSettings();
        res.json(settings);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching settings', error: err.message });
    }
});

app.put('/api/settings/backup', authMiddleware, async (req, res) => {
    try {
        const { autoBackup, backupPath } = req.body;
        await Setting.findOneAndUpdate({ key: 'autoBackup' }, { value: autoBackup }, { upsert: true });
        await Setting.findOneAndUpdate({ key: 'backupPath' }, { value: backupPath }, { upsert: true });
        await scheduleBackup();
        res.json({ message: 'Settings updated successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error updating settings', error: err.message });
    }
});

app.post('/api/backup/now', authMiddleware, async (req, res) => {
    try {
        const result = await performBackup();
        if (result.success) res.json({ message: result.message });
        else res.status(500).json({ message: result.message });
    } catch (err) {
        console.error("Manual Backup Error:", err);
        res.status(500).json({ message: 'Error performing backup', error: err.message });
    }
});

app.post('/api/backup/restore', authMiddleware, upload.single('backupFile'), (req, res) => {
    try {
        const backupFile = req.file;
        if (!backupFile) return res.status(400).json({ message: 'No backup file uploaded.' });

        const archivePath = backupFile.path;
        const command = `mongorestore --uri="${process.env.MONGO_URI}" --archive="${archivePath}" --gzip --drop`;

        exec(command, (error, stdout, stderr) => {
            try {
                fs.unlinkSync(archivePath); // Clean up uploaded file
            } catch (unlinkErr) {
                console.error("Error removing uploaded backup file:", unlinkErr);
            }

            if (error) {
                console.error(`Restore Error: ${error.message}\n${stderr}`);
                return res.status(500).json({ message: `Restore failed: ${stderr || error.message}` });
            }
            res.json({ message: 'Database restored successfully.' });
        });
    } catch (err) {
        console.error("Restore API Error:", err);
        res.status(500).json({ message: 'Error restoring database', error: err.message });
    }
});

const createNotification = async (title, message, type = 'info') => {
    try {
        const notification = new Notification({ title, message, type });
        await notification.save();
        // In a real-world app with websockets, you would emit an event here
        // to push the notification to connected clients in real-time.
    } catch (error) {
        console.error('Error creating notification:', error);
    }
};

// ===== Start Server =====
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 PC Garage Pro server running on port ${PORT}`));
