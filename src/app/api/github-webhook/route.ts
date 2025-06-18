import crypto from 'crypto';
import {NextRequest, NextResponse} from "next/server";

const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET as string; // 你Webhook填写的Secret
const GH_PAT = process.env.GH_PAT as string; // GitHub Personal Access Token
const GITHUB_OWNER = process.env.GITHUB_OWNER as string;                // 自己GitHub用户名
const GITHUB_REPO = process.env.GITHUB_REPO as string;                      // 自己fork库名
const GITHUB_WORKFLOW_ID = process.env.GITHUB_WORKFLOW_ID as string;              // 你的workflow文件名(.github/workflows/下)

const verifySignature = (payload: string, signature: string) => {
    const hmac = crypto.createHmac('sha256', GITHUB_WEBHOOK_SECRET);
    hmac.update(payload);
    const expected = 'sha256=' + hmac.digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

const fireSyncUpstream = async () => {
    const workflow_url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${GITHUB_WORKFLOW_ID}/dispatches`;
    const github_resp = await fetch(workflow_url, {
        method: 'POST',
        headers: {
            Authorization: `token ${GH_PAT}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            ref: 'main'
        })
    });
    const resp = await github_resp.text();
    if (github_resp.status === 204) {
        return new NextResponse(null, {status: 204})
    }
    console.log("fire github upstream workflow response: ", resp);
    let nextResponse = NextResponse.json({data: resp}, {status: github_resp.status});
    github_resp.headers.forEach((v, k) => nextResponse.headers.set(k, v));
    return nextResponse;
};

export const POST = async (request: NextRequest) => {
    const sig = request.headers.get("x-hub-signature-256");
    if (sig == null || request.body == null) {
        return NextResponse.json({msg: "invalid request"}, {status: 401});
    }
    if (!verifySignature(await request.text(), sig)) {
        return NextResponse.json({msg: "sign failed"}, {status: 401});
    }
    return await fireSyncUpstream();
};

export const config = {
    api: {
        bodyParser: false, // 为了能校验signature，需用raw body
    }
};