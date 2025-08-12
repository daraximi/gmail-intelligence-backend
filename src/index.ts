import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();

//Basic security middleware
app.use(helmet());
app.use(
    cors({
        origin: '*',
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'x-api-key'],
    })
);
app.use(express.json({ limit: '100kb' }));

if (!process.env.OPENAI_API_KEY || !process.env.BACKEND_API_KEY) {
    console.error('OPENAI_API_KEY or BACKEND_API_KEY is not set');
    process.exit(1);
}

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const BACKEND_API_KEY = process.env.BACKEND_API_KEY;

//Rate Limiting Per Ip
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: 'Too many requests, please try again later.',
});
app.use(limiter);

// API Key Authentication Middleware
function authenticate(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) {
    const apiKey = req.header('x-api-key');
    if (!apiKey || apiKey !== BACKEND_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// Protect all routes
app.use(authenticate);

// Routes
app.post('/analyse', async (req, res) => {
    // console.log(req.body);
    console.log('Analyse route hit');
    const { emailText } = req.body;

    if (
        !emailText ||
        typeof emailText !== 'string' ||
        emailText.length > 5000
    ) {
        return res
            .status(400)
            .json({ error: 'Invalid or too long email text.' });
    }
    try {
        const response = await fetch('https://api.openai.com/v1/responses', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${OPENAI_API_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                model: 'gpt-5',
                input: [
                    {
                        role: 'system',
                        content: `
                    You are an expert email communication advisor. Analyze the tone and sentiment of emails and provide constructive feedback.
                    Please analyze the following email and return a JSON response with:
                        1. sentiment: overall sentiment (positive, neutral, negative, or mixed)
                        2. tone: specific tone descriptors (professional, casual, aggressive, passive-aggressive, friendly, etc.)
                        3. confidence: confidence score 0-1
                        4. issues: array of potential problems
                        5. suggestions: array of specific improvement suggestions
                        6. riskLevel: low, medium, high (for workplace appropriateness)
                  `,
                    },
                    { role: 'user', content: emailText },
                ],
            }),
        });

        if (!response.ok) {
            return res
                .status(response.status)
                .json({ error: 'OpenAI API error' });
        }

        const data: any = await response.json();
        const analysis = JSON.parse(data.output[1].content[0].text);
        res.json(analysis);
    } catch (error) {
        console.error('Error analysing email', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/suggest', async (req, res) => {
    console.log('Suggest route hit');
    const { emailText, analysisResult } = req.body;

    if (!emailText || !analysisResult) {
        return res
            .status(400)
            .json({ error: 'Missing emailText or analysisResult' });
    }

    try {
        const response = await fetch('https://api.openai.com/v1/responses', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${OPENAI_API_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                model: 'gpt-5',
                input: [
                    {
                        role: 'system',
                        content:
                            'You are a professional communication coach. Give a rewritten version of the provided email to be more professional, clear, and workplace-appropriate while maintaining the original intent.',
                    },
                    {
                        role: 'user',
                        content: `Original email: "${emailText}"\n\nIssues found: ${analysisResult.issues.join(
                            ', '
                        )}\n\nPlease rewrite.`,
                    },
                ],
            }),
        });

        if (!response.ok) {
            return res
                .status(response.status)
                .json({ error: 'OpenAI API error' });
        }

        const data: any = await response.json();
        const improvedEmail = data.output[1].content[0].text;
        res.json({ improvedEmail });
    } catch (error) {
        console.error('❌ Backend error:', error);
        res.status(500).json({ error: 'Failed to suggest improvements' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Secure backend running on Port: ${PORT}`);
});
