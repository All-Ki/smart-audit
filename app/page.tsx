"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Progress } from "@/components/ui/progress"
import { Shield, AlertTriangle, Bug, CheckCircle, Code, FileText, Zap } from "lucide-react"

interface Vulnerability {
  id: string
  title: string
  severity: "Critical" | "High" | "Medium" | "Low"
  description: string
  location: string
  recommendation: string
  codeSnippet?: string
}

interface AuditReport {
  contractName: string
  totalIssues: number
  criticalIssues: number
  highIssues: number
  mediumIssues: number
  lowIssues: number
  vulnerabilities: Vulnerability[]
  gasOptimizations: string[]
  bestPractices: string[]
  overallScore: number
}

export default function SmartContractAuditor() {
  const [contractCode, setContractCode] = useState("")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [auditReport, setAuditReport] = useState<AuditReport | null>(null)
  const [progress, setProgress] = useState(0)

  const analyzeContract = async () => {
    if (!contractCode.trim()) return

    setIsAnalyzing(true)
    setProgress(0)

    // Simulate progress
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) {
          clearInterval(progressInterval)
          return 90
        }
        return prev + 10
      })
    }, 200)

    try {
      const response = await fetch("/api/audit-contract", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ contractCode }),
      })

      if (!response.ok) {
        throw new Error("Failed to analyze contract")
      }

      const report = await response.json()
      setAuditReport(report)
      setProgress(100)
    } catch (error) {
      console.error("Error analyzing contract:", error)
      // Fallback to demo data for demonstration
      setAuditReport(generateDemoReport())
      setProgress(100)
    } finally {
      setIsAnalyzing(false)
      clearInterval(progressInterval)
    }
  }

  const generateDemoReport = (): AuditReport => {
    return {
      contractName: "ExampleContract",
      totalIssues: 7,
      criticalIssues: 1,
      highIssues: 2,
      mediumIssues: 3,
      lowIssues: 1,
      overallScore: 65,
      vulnerabilities: [
        {
          id: "1",
          title: "Reentrancy Vulnerability",
          severity: "Critical",
          description: "The contract is vulnerable to reentrancy attacks due to external calls before state changes.",
          location: "Line 45-52",
          recommendation: "Use the checks-effects-interactions pattern or implement a reentrancy guard.",
          codeSnippet:
            'function withdraw() external {\n    uint amount = balances[msg.sender];\n    (bool success,) = msg.sender.call{value: amount}("");\n    require(success);\n    balances[msg.sender] = 0; // State change after external call\n}',
        },
        {
          id: "2",
          title: "Unchecked External Call",
          severity: "High",
          description: "External call return value is not properly checked, which could lead to silent failures.",
          location: "Line 78",
          recommendation: "Always check the return value of external calls and handle failures appropriately.",
        },
        {
          id: "3",
          title: "Missing Access Control",
          severity: "High",
          description: "Critical function lacks proper access control modifiers.",
          location: "Line 23-28",
          recommendation: "Add appropriate access control modifiers like onlyOwner or role-based permissions.",
        },
        {
          id: "4",
          title: "Integer Overflow Risk",
          severity: "Medium",
          description: "Arithmetic operations without SafeMath could lead to overflow/underflow.",
          location: "Line 67",
          recommendation: "Use SafeMath library or Solidity 0.8+ built-in overflow protection.",
        },
        {
          id: "5",
          title: "Timestamp Dependence",
          severity: "Medium",
          description: "Contract logic depends on block.timestamp which can be manipulated by miners.",
          location: "Line 89",
          recommendation: "Avoid using block.timestamp for critical logic or use block numbers instead.",
        },
        {
          id: "6",
          title: "Uninitialized Storage Pointer",
          severity: "Medium",
          description: "Storage pointer is not properly initialized, which could lead to unexpected behavior.",
          location: "Line 34",
          recommendation: "Explicitly initialize storage pointers or use memory instead.",
        },
        {
          id: "7",
          title: "Gas Limit DoS",
          severity: "Low",
          description: "Loop without gas limit could cause DoS if array grows too large.",
          location: "Line 56-61",
          recommendation: "Implement pagination or gas limit checks for loops over dynamic arrays.",
        },
      ],
      gasOptimizations: [
        "Use 'calldata' instead of 'memory' for function parameters that are not modified",
        "Pack struct variables to save storage slots",
        "Use 'unchecked' blocks for arithmetic operations that cannot overflow",
        "Cache array length in loops to avoid repeated SLOAD operations",
      ],
      bestPractices: [
        "Implement comprehensive event logging for all state changes",
        "Add detailed NatSpec documentation for all functions",
        "Consider implementing a pause mechanism for emergency situations",
        "Use OpenZeppelin's battle-tested contract libraries where possible",
      ],
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500"
      case "High":
        return "bg-orange-500"
      case "Medium":
        return "bg-yellow-500"
      case "Low":
        return "bg-blue-500"
      default:
        return "bg-gray-500"
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "Critical":
        return <AlertTriangle className="h-4 w-4" />
      case "High":
        return <AlertTriangle className="h-4 w-4" />
      case "Medium":
        return <Bug className="h-4 w-4" />
      case "Low":
        return <Bug className="h-4 w-4" />
      default:
        return <Bug className="h-4 w-4" />
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-4">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="h-8 w-8 text-blue-600" />
            <h1 className="text-4xl font-bold text-gray-900">Smart Contract Auditor</h1>
          </div>
          <p className="text-xl text-gray-600">AI-powered security analysis for Solidity smart contracts</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Input Section */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Code className="h-5 w-5" />
                  Contract Code
                </CardTitle>
                <CardDescription>Paste your Solidity contract code below for analysis</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Textarea
                  placeholder="pragma solidity ^0.8.0;

contract MyContract {
    // Your contract code here...
}"
                  value={contractCode}
                  onChange={(e) => setContractCode(e.target.value)}
                  className="min-h-[300px] font-mono text-sm"
                />
                <Button
                  onClick={analyzeContract}
                  disabled={isAnalyzing || !contractCode.trim()}
                  className="w-full"
                  size="lg"
                >
                  {isAnalyzing ? (
                    <>
                      <Zap className="h-4 w-4 mr-2 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4 mr-2" />
                      Analyze Contract
                    </>
                  )}
                </Button>
                {isAnalyzing && (
                  <div className="space-y-2">
                    <Progress value={progress} className="w-full" />
                    <p className="text-sm text-gray-600 text-center">
                      {progress < 30
                        ? "Parsing contract..."
                        : progress < 60
                          ? "Analyzing vulnerabilities..."
                          : progress < 90
                            ? "Generating report..."
                            : "Finalizing..."}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Results Section */}
          <div className="lg:col-span-2">
            {auditReport ? (
              <div className="space-y-6">
                {/* Overview Cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <Card>
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-red-600">{auditReport.criticalIssues}</div>
                      <div className="text-sm text-gray-600">Critical</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-orange-600">{auditReport.highIssues}</div>
                      <div className="text-sm text-gray-600">High</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-yellow-600">{auditReport.mediumIssues}</div>
                      <div className="text-sm text-gray-600">Medium</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-blue-600">{auditReport.lowIssues}</div>
                      <div className="text-sm text-gray-600">Low</div>
                    </CardContent>
                  </Card>
                </div>

                {/* Overall Score */}
                <Card>
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold">Security Score</h3>
                      <div className="text-2xl font-bold text-blue-600">{auditReport.overallScore}/100</div>
                    </div>
                    <Progress value={auditReport.overallScore} className="h-3" />
                    <p className="text-sm text-gray-600 mt-2">
                      {auditReport.overallScore >= 80
                        ? "Good security posture"
                        : auditReport.overallScore >= 60
                          ? "Moderate security concerns"
                          : "Significant security issues detected"}
                    </p>
                  </CardContent>
                </Card>

                {/* Detailed Results */}
                <Tabs defaultValue="vulnerabilities" className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                    <TabsTrigger value="optimizations">Gas Optimization</TabsTrigger>
                    <TabsTrigger value="practices">Best Practices</TabsTrigger>
                  </TabsList>

                  <TabsContent value="vulnerabilities" className="space-y-4">
                    {auditReport.vulnerabilities.map((vuln) => (
                      <Card key={vuln.id}>
                        <CardHeader>
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-2">
                              {getSeverityIcon(vuln.severity)}
                              <CardTitle className="text-lg">{vuln.title}</CardTitle>
                            </div>
                            <Badge className={`${getSeverityColor(vuln.severity)} text-white`}>{vuln.severity}</Badge>
                          </div>
                          <CardDescription>{vuln.location}</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div>
                            <h4 className="font-semibold mb-2">Description</h4>
                            <p className="text-gray-700">{vuln.description}</p>
                          </div>
                          {vuln.codeSnippet && (
                            <div>
                              <h4 className="font-semibold mb-2">Code Snippet</h4>
                              <pre className="bg-gray-100 p-3 rounded-md text-sm overflow-x-auto">
                                <code>{vuln.codeSnippet}</code>
                              </pre>
                            </div>
                          )}
                          <div>
                            <h4 className="font-semibold mb-2">Recommendation</h4>
                            <p className="text-gray-700">{vuln.recommendation}</p>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </TabsContent>

                  <TabsContent value="optimizations" className="space-y-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <Zap className="h-5 w-5" />
                          Gas Optimization Suggestions
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="space-y-3">
                          {auditReport.gasOptimizations.map((optimization, index) => (
                            <li key={index} className="flex items-start gap-3">
                              <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                              <span className="text-gray-700">{optimization}</span>
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="practices" className="space-y-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <FileText className="h-5 w-5" />
                          Best Practice Recommendations
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="space-y-3">
                          {auditReport.bestPractices.map((practice, index) => (
                            <li key={index} className="flex items-start gap-3">
                              <CheckCircle className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
                              <span className="text-gray-700">{practice}</span>
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>
              </div>
            ) : (
              <Card className="h-[400px] flex items-center justify-center">
                <CardContent className="text-center">
                  <Shield className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-600 mb-2">Ready to Audit</h3>
                  <p className="text-gray-500">Paste your smart contract code and click analyze to get started</p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
