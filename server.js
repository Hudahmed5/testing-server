const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 4000;
let server; // Add server variable to store the HTTP server instance

// Store webhook configurations (in a real app, this would be in a database)
const webhookConfigs = new Map();

// Middleware to parse JSON with raw body
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));

// Add webhook configuration endpoint
app.post('/register-webhook', (req, res) => {
    const { webhookId, secret } = req.body;
    
    if (!webhookId || !secret) {
        return res.status(400).json({
            status: 'error',
            message: 'webhookId and secret are required'
        });
    }

    webhookConfigs.set(webhookId, {
        secret,
        events: [] // Store received events for this webhook
    });

    console.log(`Registered webhook configuration: ${webhookId}`);
    res.json({
        status: 'success',
        message: 'Webhook configuration registered',
        webhookId
    });
});

// Verify webhook signature
const verifyWebhookSignature = (payload, signature, secret) => {
    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(JSON.stringify(payload))
        .digest('hex');
    
    return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
    );
};

// Webhook endpoint
app.post('/webhook', (req, res) => {
    try {
        const signature = req.headers['x-webhook-signature'];
        const event = req.headers['x-webhook-event'];
        const webhookId = req.headers['x-webhook-id']; // You'll need to add this in AlphaBit

        console.log('\n=== Webhook Request Received ===');
        console.log('Headers:', {
            signature: signature?.substring(0, 10) + '...',
            event,
            webhookId
        });

        if (!signature) {
            throw new Error('No signature provided');
        }

        if (!webhookId) {
            throw new Error('No webhook ID provided');
        }

        const config = webhookConfigs.get(webhookId);
        if (!config) {
            throw new Error('Unknown webhook configuration');
        }

        // Verify signature
        const isValid = verifyWebhookSignature(req.body, signature, config.secret);
        if (!isValid) {
            throw new Error('Invalid signature');
        }

        // Log the webhook data
        console.log('Event Type:', event);
        console.log('Timestamp:', new Date().toISOString());
        console.log('Payload:', JSON.stringify(req.body, null, 2));

        // Store the event
        config.events.push({
            timestamp: new Date(),
            event,
            payload: req.body
        });

        console.log('========================\n');

        res.status(200).json({
            status: 'success',
            message: 'Webhook processed successfully'
        });
    } catch (error) {
        console.error('Webhook Error:', error.message);
        res.status(400).json({
            status: 'error',
            message: 'Webhook verification failed',
            error: error.message
        });
    }
});

// Get events for a specific webhook
app.get('/events/:webhookId', (req, res) => {
    const { webhookId } = req.params;
    const config = webhookConfigs.get(webhookId);

    if (!config) {
        return res.status(404).json({
            status: 'error',
            message: 'Webhook configuration not found'
        });
    }

    res.json({
        status: 'success',
        webhookId,
        events: config.events
    });
});

// List all registered webhooks
app.get('/webhooks', (req, res) => {
    const webhooks = Array.from(webhookConfigs.keys()).map(id => ({
        id,
        eventCount: webhookConfigs.get(id).events.length
    }));

    res.json({
        status: 'success',
        webhooks
    });
});

// Modified server startup
server = app.listen(port, () => {
    console.log(`\n=== Webhook Testing Server ===`);
    console.log(`Server running on port ${port}`);
    console.log(`Railway URL: ${process.env.RAILWAY_STATIC_URL || 'http://localhost:' + port}`);
    console.log(`\nEndpoints:`);
    console.log(`- Webhook URL: /webhook`);
    console.log(`- Register webhook: POST /register-webhook`);
    console.log(`- List webhooks: GET /webhooks`);
    console.log(`- Get events: GET /events/:webhookId`);
    console.log(`\nTo register a webhook, send POST to /register-webhook:`);
    console.log({
        webhookId: "whk_your_webhook_id",
        secret: "your_webhook_secret"
    });
    console.log(`\n=========================\n`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
    });
}); 