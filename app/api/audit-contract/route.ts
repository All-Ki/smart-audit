import { type NextRequest, NextResponse } from "next/server"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"

export async function POST(request: NextRequest) {
  try {
    const { contractCode } = await request.json()

    if (!contractCode) {
      return NextResponse.json({ error: "Contract code is required" }, { status: 400 })
    }

    const { text } = await generateText({
      model: openai("gpt-4o"),
      system: `You are an expert smart contract security auditor. Analyze the provided Solidity contract code and identify security vulnerabilities, gas optimization opportunities, and best practice violations.

Return your analysis as a JSON object with the following structure:
{
  "contractName": "string",
  "totalIssues": number,
  "criticalIssues": number,
  "highIssues": number,
  "mediumIssues": number,
  "lowIssues": number,
  "overallScore": number (0-100),
  "vulnerabilities": [
    {
      "id": "string",
      "title": "string",
      "severity": "Critical|High|Medium|Low",
      "description": "string",
      "location": "string (line numbers or function names)",
      "recommendation": "string",
      "codeSnippet": "string (optional)"
    }
  ],
  "gasOptimizations": ["string array of optimization suggestions"],
  "bestPractices": ["string array of best practice recommendations"]
}

Focus on common vulnerabilities like:
- Reentrancy attacks
- Integer overflow/underflow
- Access control issues
- Unchecked external calls
- Timestamp dependence
- DoS attacks
- Front-running
- Uninitialized storage pointers
- Gas limit issues

Provide specific, actionable recommendations for each issue found.`,
      prompt: `Please analyze this Solidity smart contract for security vulnerabilities and provide a comprehensive audit report:

\`\`\`solidity
${contractCode}
\`\`\`

Return only the JSON response without any additional text or formatting.`,
    })

    // Parse the AI response as JSON
    let auditReport
    try {
      auditReport = JSON.parse(text)
    } catch (parseError) {
      console.error("Failed to parse AI response:", parseError)
      // Return a fallback response if parsing fails
      return NextResponse.json({
        contractName: "Unknown Contract",
        totalIssues: 0,
        criticalIssues: 0,
        highIssues: 0,
        mediumIssues: 0,
        lowIssues: 0,
        overallScore: 50,
        vulnerabilities: [],
        gasOptimizations: ["Unable to analyze - please check contract syntax"],
        bestPractices: ["Ensure contract compiles without errors"],
      })
    }

    return NextResponse.json(auditReport)
  } catch (error) {
    console.error("Error in audit analysis:", error)
    return NextResponse.json({ error: "Failed to analyze contract" }, { status: 500 })
  }
}
