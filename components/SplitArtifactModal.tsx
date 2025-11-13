

import React, { useState, useEffect, useCallback } from 'react';
import type { InvestigationArtifact } from '../types';
import { splitAndClassifyArtifact, SplitArtifactResult } from '../services/geminiService';
import { XCircleIcon, LightBulbIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

interface SplitArtifactModalProps {
    artifact: InvestigationArtifact;
    onClose: () => void;
    onConfirmSplit: (newArtifactsData: SplitArtifactResult[]) => void;
}

const stringifyContent = (content: InvestigationArtifact['content']): string => {
    if (typeof content === 'object' && content !== null) {
        if ('text' in content) return (content as { text: string }).text;
        if ('content' in content) return (content as { content: string }).content;
        return JSON.stringify(content);
    }
    return String(content);
};

const SplitArtifactModal: React.FC<SplitArtifactModalProps> = ({ artifact, onClose, onConfirmSplit }) => {
    const { t } = useLocalization();
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [splitResults, setSplitResults] = useState<SplitArtifactResult[]>([]);

    const getSuggestion = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            const contentString = stringifyContent(artifact.content);
            const results = await splitAndClassifyArtifact(contentString);
            setSplitResults(results);
        } catch (err) {
            setError(t('error_splitSuggestionFailed'));
        } finally {
            setIsLoading(false);
        }
    }, [artifact.content, t]);

    useEffect(() => {
        getSuggestion();
    }, [getSuggestion]);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (splitResults.length > 0) {
            onConfirmSplit(splitResults);
        }
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fade-in" onClick={onClose}>
            <div className="bg-sentinel-gray-medium w-full max-w-2xl rounded-xl shadow-2xl border border-sentinel-gray-light flex flex-col" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between p-4 border-b border-sentinel-gray-light">
                    <h2 className="text-xl font-bold text-gray-100 flex items-center">
                        <LightBulbIcon className="h-6 w-6 me-2 text-sentinel-blue" />
                        {t('aiOrganizationPlan')}
                    </h2>
                    <button onClick={onClose} className="text-gray-400 hover:text-white"><XCircleIcon className="h-8 w-8" /></button>
                </div>
                
                <form onSubmit={handleSubmit}>
                    <div className="p-6 space-y-4">
                        <p className="text-sm text-gray-400">{t('aiOrganizationPlan_desc')}</p>
                        
                        {isLoading && (
                            <div className="flex flex-col items-center justify-center space-y-2 py-8">
                                <div className="w-8 h-8 border-2 border-dashed rounded-full animate-spin border-sentinel-blue"></div>
                                <span className="text-gray-400">{t('analyzingAndSplitting')}</span>
                            </div>
                        )}
                        {error && <p className="text-red-400 text-center py-8 bg-red-900/30 rounded-md">{error}</p>}
                        
                        {!isLoading && !error && splitResults.length > 0 && (
                            <div className="space-y-3 max-h-80 overflow-y-auto pe-2">
                                {splitResults.map((result, index) => (
                                    <div key={index} className="p-3 bg-sentinel-gray-dark rounded-md border border-sentinel-gray-light">
                                        <div className="flex justify-between items-center mb-2">
                                            <p className="font-semibold text-gray-200 truncate">{result.title}</p>
                                            <span className="text-xs bg-sentinel-blue/80 text-white px-2 py-0.5 rounded-full">{t(result.phase)}</span>
                                        </div>
                                        <p className="text-sm text-gray-400">{result.summary}</p>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                    <div className="p-4 bg-sentinel-gray-dark/50 border-t border-sentinel-gray-light flex justify-end gap-3 rounded-b-xl">
                        <button type="button" onClick={onClose} className="px-4 py-2 text-sm rounded-md bg-sentinel-gray-light hover:bg-gray-600">{t('cancel')}</button>
                        <button type="submit" disabled={isLoading || error !== null || splitResults.length === 0} className="px-4 py-2 text-sm rounded-md bg-sentinel-blue hover:bg-cyan-600 text-white disabled:opacity-50">{t('approveAndOrganize')}</button>
                    </div>
                </form>
            </div>
             <style>{`
                @keyframes fade-in {
                    from { opacity: 0; transform: scale(0.95); }
                    to { opacity: 1; transform: scale(1); }
                }
                .animate-fade-in {
                    animation: fade-in 0.2s ease-out forwards;
                }
            `}</style>
        </div>
    );
};

export default SplitArtifactModal;