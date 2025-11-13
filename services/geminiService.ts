

import { GoogleGenAI, Type } from "@google/genai";
import type { AnalysisResult, ChecklistItem, KillChainPhase, InvestigationArtifact, IndicatorOfCompromise, ArtifactContent, UserAgentSecurityAnalysis } from '../types';

if (!process.env.API_KEY) {
  throw new Error("API_KEY environment variable not set");
}

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

const analysisSchema = {
  type: Type.OBJECT,
  properties: {
    summary: { type: Type.STRING, description: "A concise, easy-to-understand summary of what happened." },
    estimated_severity: {
      type: Type.STRING,
      enum: ["Informational", "Low", "Medium", "High", "Critical"],
      description: "Assessment of the event's severity."
    },
    attack_tactic: {
      type: Type.OBJECT,
      description: "The most likely MITRE ATT&CK Tactic.",
      properties: {
        id: { type: Type.STRING },
        name: { type: Type.STRING },
        description: { type: Type.STRING }
      },
      required: ["id", "name", "description"]
    },
    attack_technique: {
      type: Type.OBJECT,
      description: "The most likely MITRE ATT&CK Technique that corresponds to the Tactic.",
      properties: {
        id: { type: Type.STRING },
        name: { type: Type.STRING },
        description: { type: Type.STRING }
      },
      required: ["id", "name", "description"]
    },
    indicators_of_compromise: {
      type: Type.ARRAY,
      description: "A list of all indicators of compromise (IoCs) found in the event.",
      items: {
        type: Type.OBJECT,
        properties: {
          type: { type: Type.STRING, enum: ['IP Address', 'File Hash', 'Domain', 'URL', 'Email', 'Other'] },
          value: { type: Type.STRING }
        },
        required: ["type", "value"]
      }
    },
    investigation_checklist: {
      type: Type.ARRAY,
      description: "A checklist of recommended next steps for a junior analyst.",
      items: {
        type: Type.OBJECT,
        properties: {
          step: { type: Type.INTEGER },
          action: { type: Type.STRING, description: "A short, actionable title for the step." },
          details: { type: Type.STRING, description: "A more detailed explanation of what to do." }
        },
        required: ["step", "action", "details"]
      }
    },
    timeline_events: {
        type: Type.ARRAY,
        description: "A chronological list of key events that occurred.",
        items: {
            type: Type.OBJECT,
            properties: {
                timestamp: { type: Type.STRING, description: "The timestamp of the event (e.g., YYYY-MM-DD HH:MM:SS UTC). Use the original if available, otherwise estimate." },
                event: { type: Type.STRING, description: "A description of the event." }
            },
            required: ["timestamp", "event"]
        }
    }
  },
  required: ["summary", "estimated_severity", "attack_tactic", "attack_technique", "indicators_of_compromise", "investigation_checklist", "timeline_events"]
};

export const analyzeEvent = async (eventLog: string): Promise<AnalysisResult> => {
  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: `Analyze the following security event log and provide a structured analysis. The user is a junior security analyst, so be clear and concise. Event Log: \n\n${eventLog}`,
    config: {
      responseMimeType: 'application/json',
      responseSchema: analysisSchema,
    }
  });
  
  const jsonText = response.text.trim();
  return JSON.parse(jsonText) as AnalysisResult;
};


export const suggestNextSteps = async (caseContext: string): Promise<Omit<ChecklistItem, 'completed'>[]> => {
    const checklistSchema = {
        type: Type.OBJECT,
        properties: {
            steps: {
                type: Type.ARRAY,
                description: "A checklist of recommended next steps.",
                items: {
                    type: Type.OBJECT,
                    properties: {
                        step: { type: Type.INTEGER },
                        action: { type: Type.STRING, description: "A short, actionable title for the step." },
                        details: { type: Type.STRING, description: "A more detailed explanation of what to do." }
                    },
                    required: ["step", "action", "details"]
                }
            }
        },
        required: ["steps"]
    };

    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `Based on the following security investigation case context, suggest a short list of 3-5 high-level, actionable next steps for a security analyst.
IMPORTANT: The analyst's role is INVESTIGATION and ANALYSIS only. DO NOT suggest operational tasks like "contain the host," "block the IP," or "reset passwords."
Focus exclusively on analytical actions like "Correlate IP addresses with firewall logs," "Research the file hash on threat intel platforms," or "Analyze the PowerShell script for obfuscation techniques." Frame your suggestions as recommendations.

Case Context:
${caseContext}`,
        config: {
            responseMimeType: 'application/json',
            responseSchema: checklistSchema,
        }
    });

    const jsonText = response.text.trim();
    const result = JSON.parse(jsonText) as { steps: Omit<ChecklistItem, 'completed'>[] };
    return result.steps;
};


export const generatePhaseIndex = async (artifacts: InvestigationArtifact[]): Promise<string> => {
    if (artifacts.length === 0) {
        return "No activity recorded for this phase yet.";
    }
    const context = artifacts.map(a => `Title: ${a.title}\nContent: ${JSON.stringify(a.content)}`).join('\n\n');
    
    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `Summarize the key findings from the following investigation artifacts for a specific phase of an attack. Provide a concise, bulleted list of the most important points.

Artifacts:
${context}`,
    });

    return response.text;
};

export type SplitArtifactResult = {
    phase: KillChainPhase;
    title: string;
    summary: string;
};

export const splitAndClassifyArtifact = async (content: string): Promise<SplitArtifactResult[]> => {
    const splitSchema = {
        type: Type.OBJECT,
        properties: {
            chunks: {
                type: Type.ARRAY,
                description: "An array of classified chunks from the original text.",
                items: {
                    type: Type.OBJECT,
                    properties: {
                        phase: { type: Type.STRING, enum: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Command and Control', 'Actions on Objectives'] },
                        title: { type: Type.STRING, description: "A concise, descriptive title for this specific chunk of information." },
                        summary: { type: Type.STRING, description: "The relevant text content for this chunk." }
                    },
                    required: ["phase", "title", "summary"]
                }
            }
        },
        required: ["chunks"]
    };

    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are an expert security analyst tasked with organizing raw investigation notes. Analyze the following text blob. Identify distinct topics or findings within it. For each distinct finding, create a new artifact with a clear title, a summary of the finding, and classify it into the most appropriate Cyber Kill Chain phase. If the text contains multiple distinct topics, split it into multiple artifacts. If all the text belongs to a single topic, create one artifact for it.

Raw Text:
${content}`,
        config: {
            responseMimeType: 'application/json',
            responseSchema: splitSchema,
        }
    });

    const jsonText = response.text.trim();
    const result = JSON.parse(jsonText) as { chunks: SplitArtifactResult[] };
    return result.chunks;
};


export const generateGlobalSummary = async (caseContext: string): Promise<string> => {
    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are an expert security analyst. Based on the entire case context provided, write a high-level executive summary of the investigation so far. Describe the likely attack narrative, what is known, and what is still unknown.

Case Context:
${caseContext}`,
    });

    return response.text;
};

const iocSchema = {
    type: Type.OBJECT,
    properties: {
        iocs: {
            type: Type.ARRAY,
            description: "A list of all indicators of compromise (IoCs) found in the text.",
            items: {
                type: Type.OBJECT,
                properties: {
                    type: { type: Type.STRING, enum: ['IP Address', 'File Hash', 'Domain', 'URL', 'Email', 'Other'] },
                    value: { type: Type.STRING },
                    killChainPhase: { type: Type.STRING, enum: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Command and Control', 'Actions on Objectives', 'Uncategorized'] }
                },
                required: ["type", "value", "killChainPhase"]
            }
        }
    },
    required: ["iocs"]
};

const stringifyArtifactContent = (content: ArtifactContent): string => {
    if ('summary' in content) return `AI Analysis Summary: ${content.summary}`;
    if ('text' in content) return content.text;
    if ('output' in content) return `Tool: ${content.toolName}\nCommand: ${content.command || 'N/A'}\nOutput:\n${content.output}`;
    if ('fileName' in content) return `File: ${content.fileName}\nContent:\n${content.content}`;
    return JSON.stringify(content);
}

export const generateGlobalIoCs = async (artifacts: InvestigationArtifact[]): Promise<{ iocsByPhase: Partial<Record<KillChainPhase, IndicatorOfCompromise[]>> }> => {
    const context = artifacts
        .filter(a => a.type !== 'CASE_INDEX' && a.type !== 'TOOL_INFO' && a.type !== 'GLOBAL_SUMMARY' && a.type !== 'GLOBAL_IOC_LIST')
        .map(a => `--- Artifact (Phase: ${a.killChainPhase}) ---\n${stringifyArtifactContent(a.content)}`)
        .join('\n\n');

    if (!context.trim()) {
        return { iocsByPhase: {} };
    }
    
    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are an expert security analyst specializing in Indicator of Compromise (IoC) extraction. Read through all the following artifacts from an investigation. Extract every single IoC you can find, even if it's buried in unstructured text. For each IoC, classify its type and associate it with the Kill Chain Phase of the artifact where it was found.

Investigation Artifacts:
${context}`,
        config: {
            responseMimeType: 'application/json',
            responseSchema: iocSchema,
        }
    });

    const jsonText = response.text.trim();
    const result = JSON.parse(jsonText) as { iocs: (IndicatorOfCompromise & { killChainPhase: KillChainPhase })[] };

    const iocsByPhase: Partial<Record<KillChainPhase, IndicatorOfCompromise[]>> = {};

    for (const ioc of result.iocs) {
        const phase = ioc.killChainPhase;
        if (!iocsByPhase[phase]) {
            iocsByPhase[phase] = [];
        }
        // Avoid duplicates within the same phase
        if (!iocsByPhase[phase]!.some(existing => existing.value === ioc.value)) {
            iocsByPhase[phase]!.push({ type: ioc.type, value: ioc.value });
        }
    }

    return { iocsByPhase };
};

export const chatWithCaseAssistant = async (userMessage: string, caseContext: string): Promise<string> => {
    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are a world-class senior security analyst AI assistant, named Cyber Sentinel. The user is currently investigating a case. Below is the full context of the case, followed by the user's latest message. Your task is to analyze their message in the context of the case and provide a helpful, concise, and accurate response. You can answer questions, summarize artifacts, suggest investigation steps, and even formulate search queries for the tools mentioned in the 'Investigation Context' artifacts.

--- CASE CONTEXT ---
${caseContext}
--- END CASE CONTEXT ---

User Message: "${userMessage}"`,
    });

    return response.text;
};


const userAgentAnalysesSchema = {
    type: Type.OBJECT,
    properties: {
        analyses: {
            type: Type.ARRAY,
            description: "An array of security analyses for the provided User-Agent strings.",
            items: {
                type: Type.OBJECT,
                properties: {
                    userAgent: { type: Type.STRING, description: "The original User-Agent string being analyzed." },
                    summary: { type: Type.STRING, description: "A concise summary of potential security risks associated with the User-Agent string. Note if it appears to be a common browser, a bot, a scanner, or indicates an outdated/vulnerable software version." },
                    risk_level: {
                        type: Type.STRING,
                        enum: ["Informational", "Low", "Medium", "High", "Critical"],
                        description: "Assessment of the security risk level."
                    },
                },
                required: ["userAgent", "summary", "risk_level"]
            }
        }
    },
    required: ["analyses"]
};

export const analyzeUserAgentsSecurity = async (userAgentsWithParsedData: { userAgent: string, parsedData: any }[]): Promise<(UserAgentSecurityAnalysis & { userAgent: string })[]> => {
    const formattedData = userAgentsWithParsedData.map(item => 
        `User-Agent: "${item.userAgent}"\nParsed Data: ${JSON.stringify(item.parsedData, null, 2)}`
    ).join('\n---\n');
    
    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are a security analyst. I have parsed several User-Agent strings and have some preliminary data, including some security flags. Please analyze each one and provide a concise security summary and risk level. Pay attention to outdated versions, anomalies, and any security flags that are true.

List of User-Agents and their parsed data:
${formattedData}`,
        config: {
            responseMimeType: 'application/json',
            responseSchema: userAgentAnalysesSchema,
        }
    });

    const jsonText = response.text.trim();
    const result = JSON.parse(jsonText) as { analyses: (UserAgentSecurityAnalysis & { userAgent: string })[] };
    return result.analyses;
};