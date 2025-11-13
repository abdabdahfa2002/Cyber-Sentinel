

import React, { useState } from 'react';
import { useLocalization } from '../contexts/LocalizationContext';
import { BrainIcon, FingerPrintIcon, AlertTriangleIcon, DocumentTextIcon, UploadIcon } from './icons';
import { parseUserAgent } from '../services/userAgentService';
import { analyzeUserAgentsSecurity } from '../services/geminiService';
import type { UserAgentAnalysisResult, UserAgentSecurityAnalysis } from '../types';

const riskConfig = {
    Informational: { color: 'text-blue-400', bgColor: 'bg-blue-900/50', borderColor: 'border-blue-700' },
    Low: { color: 'text-green-400', bgColor: 'bg-green-900/50', borderColor: 'border-green-700' },
    Medium: { color: 'text-yellow-400', bgColor: 'bg-yellow-900/50', borderColor: 'border-yellow-700' },
    High: { color: 'text-orange-400', bgColor: 'bg-orange-900/50', borderColor: 'border-orange-700' },
    Critical: { color: 'text-red-400', bgColor: 'bg-red-900/50', borderColor: 'border-red-700' },
};

const UserAgentResultCard: React.FC<{ result: UserAgentAnalysisResult }> = ({ result }) => {
    const { t } = useLocalization();
    const security = result.security;
    const config = security ? riskConfig[security.risk_level] : riskConfig.Informational;
    const parsed = result.parsed;

    const securityFlags: string[] = parsed ? Object.entries(parsed)
        .filter(([key, value]) => key.startsWith('is_') && value === true && !['is_mobile', 'is_tablet', 'is_desktop'].includes(key))
        .map(([key]) => key.replace('is_', '')) : [];

    const DetailItem: React.FC<{ label: string; value?: string }> = ({ label, value }) =>
        value ? <div className="text-sm"><strong className="text-gray-400">{label}:</strong> <span className="text-gray-200">{value}</span></div> : null;

    return (
        <div className="bg-sentinel-gray-medium rounded-lg shadow-lg border border-sentinel-gray-light animate-fade-in">
            <div className="p-3 bg-sentinel-gray-dark/50 border-b border-sentinel-gray-light">
                <code className="text-xs text-cyan-300 break-all">{result.userAgentString}</code>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-sentinel-gray-light">
                <div className="bg-sentinel-gray-medium p-4">
                    <h3 className="font-semibold text-gray-100 mb-3 flex items-center"><FingerPrintIcon className="h-5 w-5 me-2 text-sentinel-blue" />{t('parsedInformation')}</h3>
                    {result.parseError && <p className="text-sm text-red-400">{result.parseError}</p>}
                    {result.parsed && (
                        <div className="space-y-2">
                            <DetailItem label={t('browser')} value={`${result.parsed.browser_name || 'N/A'} ${result.parsed.browser_version || ''}`} />
                            <DetailItem label={t('os')} value={`${result.parsed.os_name || 'N/A'} ${result.parsed.os_version || ''}`} />
                            <DetailItem label={t('platform')} value={`${result.parsed.platform || 'N/A'}`} />
                             <DetailItem label={t('engine')} value={`${result.parsed.engine_name || 'N/A'} ${result.parsed.engine_version || ''}`} />
                            {securityFlags.length > 0 && (
                                <div>
                                    <strong className="text-gray-400 text-sm">{t('securityFlags')}:</strong>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                        {securityFlags.map(flag => (
                                            <span key={flag} className="px-2 py-0.5 text-xs bg-yellow-900/70 text-yellow-300 rounded-full">{t(flag) || flag}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
                <div className="bg-sentinel-gray-medium p-4">
                    <h3 className="font-semibold text-gray-100 mb-3 flex items-center"><BrainIcon className="h-5 w-5 me-2 text-sentinel-blue" />{t('aiSecurityAnalysis')}</h3>
                    {result.securityError && <p className="text-sm text-red-400">{result.securityError}</p>}
                    {result.security && (
                        <div className="space-y-3">
                            <div className={`flex items-center px-3 py-1 rounded-full text-sm font-semibold ${config.bgColor} ${config.color} border ${config.borderColor} w-fit`}>
                                <AlertTriangleIcon className="h-4 w-4 me-2" />
                                {t('riskLevel')}: {t(security.risk_level)}
                            </div>
                            <p className="text-sm text-gray-300 leading-relaxed">{security.summary}</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

const UserAgentAnalyzer: React.FC = () => {
    const { t } = useLocalization();
    const [uaInput, setUaInput] = useState<string>('');
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [results, setResults] = useState<UserAgentAnalysisResult[]>([]);
    const [error, setError] = useState<string | null>(null);

    const parseInput = (input: string): string[] => {
        return input.split('\n').map(s => s.trim()).filter(Boolean);
    };

    const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target?.result as string;
            setUaInput(text);
        };
        reader.readAsText(file);
    };

    const handleAnalyze = async () => {
        setIsLoading(true);
        setResults([]);
        setError(null);
        const userAgents = parseInput(uaInput);
        if (userAgents.length === 0) {
          setError('Please enter at least one User-Agent string.');
          setIsLoading(false);
          return;
        }
    
        const analysisPromises = userAgents.map(async (ua): Promise<UserAgentAnalysisResult> => {
          let parsedData: any = null;
          let parseError: string | undefined;
    
          try {
            parsedData = await parseUserAgent(ua);
          } catch (err: unknown) {
            console.error(err);
            const error = err instanceof Error ? err : new Error(String(err));
             if (error instanceof TypeError && error.message === 'Failed to fetch') {
                parseError = 'Network Error: The User-Agent parsing service or CORS proxy may be unavailable. Please try again later.';
            } else {
                parseError = `${t('error_uaParse')} ${error.message}`;
            }
          }
    
          return {
            userAgentString: ua,
            parsed: parsedData,
            parseError: parseError,
            security: null, // Will be filled in the next step
          };
        });
    
        let preliminaryResults = await Promise.all(analysisPromises);
    
        const validResults = preliminaryResults.filter(r => r.parsed);
        if (validResults.length > 0) {
          try {
            const securityAnalyses = await analyzeUserAgentsSecurity(
              validResults.map(r => ({ userAgent: r.userAgentString, parsedData: r.parsed }))
            );
            
            preliminaryResults = preliminaryResults.map(res => {
              if (res.parsed) {
                const securityData = securityAnalyses.find(sa => sa.userAgent === res.userAgentString);
                if (securityData) {
                  return { ...res, security: { summary: securityData.summary, risk_level: securityData.risk_level } };
                }
              }
              return res;
            });
          } catch (err: unknown) {
            console.error(err);
            const error = err instanceof Error ? err : new Error(String(err));
            let errorMessage: string;
            if (error instanceof TypeError && error.message === 'Failed to fetch') {
                errorMessage = 'Network Error: The AI model may be unavailable. Please check your connection and try again later.';
            } else {
                errorMessage = `${t('error_uaSecurity')} ${error.message}`;
            }
            setError(errorMessage);
            // Add security error to each result that was supposed to get an analysis
            const validUserAgents = new Set(validResults.map(r => r.userAgentString));
            preliminaryResults = preliminaryResults.map(res => {
              if (validUserAgents.has(res.userAgentString)) {
                return { ...res, securityError: errorMessage };
              }
              return res;
            });
          }
        }
        
        setResults(preliminaryResults);
        setIsLoading(false);
    };

    return (
        <div className="max-w-6xl mx-auto space-y-6">
            <div className="bg-sentinel-gray-medium rounded-lg shadow-xl border border-sentinel-gray-light p-6">
                <p className="text-center text-gray-400 mb-6">{t('uaAnalyzer_desc')}</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <textarea
                        rows={8}
                        className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-3 text-gray-200 focus:ring-2 focus:ring-sentinel-blue placeholder-gray-500 font-mono text-sm"
                        placeholder={t('pasteUA_placeholder')}
                        value={uaInput}
                        onChange={(e) => setUaInput(e.target.value)}
                        disabled={isLoading}
                    />
                    <div className="flex justify-center items-center w-full">
                        <label htmlFor="file-upload-ua" className="flex flex-col justify-center items-center w-full h-full bg-sentinel-gray-dark rounded-lg border-2 border-sentinel-gray-light border-dashed cursor-pointer hover:bg-sentinel-gray-light">
                            <UploadIcon className="w-10 h-10 mb-3 text-gray-400" />
                            <p className="mb-2 text-sm text-gray-400"><span className="font-semibold">{t('clickToUpload')}</span> {t('orDragAndDrop')}</p>
                            <p className="text-xs text-gray-500">{t('upload_desc')}</p>
                            <input id="file-upload-ua" type="file" className="hidden" accept=".txt" onChange={handleFileChange} disabled={isLoading}/>
                        </label>
                    </div>
                </div>
                 <div className="mt-6 flex justify-end">
                    <button
                        onClick={handleAnalyze}
                        disabled={isLoading || !uaInput.trim()}
                        className="w-full sm:w-auto flex items-center justify-center px-8 py-3 border border-transparent text-base font-medium rounded-md text-white bg-sentinel-blue hover:bg-cyan-600 disabled:opacity-50"
                    >
                         {isLoading ? (
                            <>
                                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                                {t('analyzing')}...
                            </>
                        ) : t('analyze')}
                    </button>
                </div>
            </div>
            {error && (
                <div className="p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-300 text-center">
                    <p className="font-bold">{t('analysisError')}</p>
                    <p>{error}</p>
                </div>
            )}
            {results.length > 0 && (
                <div className="space-y-4">
                    {results.map((res, index) => (
                        <UserAgentResultCard key={`${res.userAgentString}-${index}`} result={res} />
                    ))}
                </div>
            )}
             <style>{`
                @keyframes fade-in {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .animate-fade-in {
                    animation: fade-in 0.3s ease-out forwards;
                }
            `}</style>
        </div>
    );
};

export default UserAgentAnalyzer;