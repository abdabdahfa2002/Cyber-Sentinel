
import React from 'react';
import type { InvestigationArtifact, AnalysisResult, ArtifactContent, KillChainPhase, IndicatorOfCompromise, IocType } from '../types';
import AnalysisDashboard from './AnalysisDashboard';
import { BrainIcon, PencilSquareIcon, CommandLineIcon, DocumentArrowUpIcon, InfoIcon, Cog6ToothIcon, LightBulbIcon, DocumentTextIcon, ListBulletIcon, GlobeAltIcon, HashIcon, LinkIcon, AtSymbolIcon, QuestionMarkCircleIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

const isAnalysisResult = (content: ArtifactContent): content is AnalysisResult => 'summary' in content;
const isTextContent = (content: ArtifactContent): content is { text: string } => 'text' in content && !('toolName' in content) && !('fileName' in content) && !('iocsByPhase' in content);
const isToolOutput = (content: ArtifactContent): content is { toolName: string; command?: string; output: string } => 'toolName' in content && 'output' in content;
const isEvidenceFile = (content: ArtifactContent): content is { fileName: string; fileType: string; content: string } => 'fileName' in content;
const isToolInfo = (content: ArtifactContent): content is { toolName: string; version?: string; configuration?: string; } => 'toolName' in content && !('output' in content);
const isGlobalIoCList = (content: ArtifactContent): content is { iocsByPhase: Partial<Record<KillChainPhase, IndicatorOfCompromise[]>> } => 'iocsByPhase' in content;

interface ArtifactCardProps {
    artifact: InvestigationArtifact;
    onOrganize?: (artifact: InvestigationArtifact) => void;
}

const IocIcon: React.FC<{ type: IocType, className?: string }> = ({ type, className = "h-4 w-4 text-sentinel-blue" }) => {
    switch(type) {
        case 'IP Address': return <GlobeAltIcon className={className} />;
        case 'File Hash': return <HashIcon className={className} />;
        case 'Domain': return <GlobeAltIcon className={className} />;
        case 'URL': return <LinkIcon className={className} />;
        case 'Email': return <AtSymbolIcon className={className} />;
        default: return <QuestionMarkCircleIcon className={className} />;
    }
};

const ArtifactCard: React.FC<ArtifactCardProps> = ({ artifact, onOrganize }) => {
    const { t } = useLocalization();
    
    const getIcon = (type: InvestigationArtifact['type']) => {
        const iconClass = "h-5 w-5 me-3 text-sentinel-blue flex-shrink-0";
        switch (type) {
            case 'AI_ANALYSIS': return <BrainIcon className={iconClass} />;
            case 'ANALYST_NOTE': return <PencilSquareIcon className={iconClass} />;
            case 'TOOL_OUTPUT': return <CommandLineIcon className={iconClass} />;
            case 'EVIDENCE_FILE': return <DocumentArrowUpIcon className={iconClass} />;
            case 'TOOL_INFO': return <Cog6ToothIcon className={iconClass} />;
            case 'CASE_INDEX': return <InfoIcon className={iconClass} />;
            case 'GLOBAL_SUMMARY': return <DocumentTextIcon className={iconClass} />;
            case 'GLOBAL_IOC_LIST': return <ListBulletIcon className={iconClass} />;
            default: return null;
        }
    };

    const renderContent = () => {
        const { type, content } = artifact;

        if (type === 'AI_ANALYSIS' && isAnalysisResult(content)) {
            return <AnalysisDashboard result={content} />;
        }
        if ((type === 'ANALYST_NOTE' || type === 'CASE_INDEX' || type === 'GLOBAL_SUMMARY') && isTextContent(content)) {
            const baseClass = "prose prose-sm prose-invert max-w-none text-gray-300 whitespace-pre-wrap p-4";
            if(type === 'CASE_INDEX') return <div className="p-4 text-sm text-gray-300 bg-sentinel-blue/10 border-t border-sentinel-blue/20">{content.text}</div>;
            return <div className={baseClass}>{content.text}</div>;
        }
        if (type === 'TOOL_OUTPUT' && isToolOutput(content)) {
            return (
                <div className="p-4 text-sm">
                    <div className="flex items-center gap-4 mb-2"><strong className="text-gray-400">{t('tool')}:</strong><span className="font-semibold text-cyan-300">{content.toolName}</span></div>
                    {content.command && (<div className="flex items-start gap-4 mb-3"><strong className="text-gray-400">{t('command')}:</strong><code className="text-xs bg-sentinel-gray-darker p-2 rounded-md text-gray-300 w-full break-all">{content.command}</code></div>)}
                    <strong className="text-gray-400 block mb-1">{t('output')}:</strong>
                    <pre className="bg-black/50 p-3 rounded-md text-xs text-gray-300 max-h-60 overflow-auto w-full"><code>{content.output}</code></pre>
                </div>
            );
        }
        if (type === 'EVIDENCE_FILE' && isEvidenceFile(content)) {
            return (
                 <div className="p-4 text-sm">
                    <div className="flex items-center gap-4 mb-3">
                        <strong className="text-gray-400">{t('fileName')}:</strong><span className="font-semibold text-cyan-300">{content.fileName}</span>
                        <span className="text-xs bg-sentinel-gray-light px-2 py-1 rounded-full">{content.fileType}</span>
                    </div>
                    <strong className="text-gray-400 block mb-1">{t('content')}:</strong>
                    <pre className="bg-black/50 p-3 rounded-md text-xs text-gray-300 max-h-60 overflow-auto w-full"><code>{content.content}</code></pre>
                </div>
            );
        }
        if (type === 'TOOL_INFO' && isToolInfo(content)) {
            return (
                <div className="p-4 text-sm space-y-2">
                    <div><strong className="text-gray-400 w-24 inline-block">{t('tool')}:</strong><span className="font-semibold text-cyan-300">{content.toolName}</span></div>
                    {content.version && <div><strong className="text-gray-400 w-24 inline-block">{t('version')}:</strong><span>{content.version}</span></div>}
                    {content.configuration && <div><strong className="text-gray-400 w-24 inline-block">{t('config')}:</strong><span className="whitespace-pre-wrap">{content.configuration}</span></div>}
                </div>
            );
        }
        if (type === 'GLOBAL_IOC_LIST' && isGlobalIoCList(content)) {
            const phasesWithIocs = Object.keys(content.iocsByPhase).filter(phase => content.iocsByPhase[phase as KillChainPhase]?.length > 0);
            if (phasesWithIocs.length === 0) {
                return <p className="text-gray-400 p-4 text-sm">{t('noIocsIdentified')}</p>
            }
            return (
                <div className="p-4 space-y-3 max-h-96 overflow-y-auto">
                    {phasesWithIocs.map(phase => (
                        <div key={phase}>
                            <h4 className="font-semibold text-sm text-sentinel-blue mb-2">{t(phase)}</h4>
                            <div className="space-y-2">
                                {content.iocsByPhase[phase as KillChainPhase]?.map((ioc, index) => (
                                     <div key={index} className="bg-sentinel-gray-darker p-2 rounded-md flex items-center">
                                        <IocIcon type={ioc.type} />
                                        <span className="ms-3 text-xs font-semibold text-gray-400 me-2">{ioc.type}:</span>
                                        <code className="text-xs text-cyan-300 break-all">{ioc.value}</code>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            );
        }
        
        return <p className="text-gray-400 p-4">{t('unsupportedArtifact')}</p>;
    }
    
    const isSplittable = onOrganize && (artifact.type === 'ANALYST_NOTE' || artifact.type === 'EVIDENCE_FILE');

    if (artifact.type === 'CASE_INDEX') {
        return (
            <div className="bg-sentinel-gray-dark rounded-lg border border-sentinel-blue/30 my-2">
                <div className="flex items-center p-2 border-b border-sentinel-blue/20">
                    {getIcon(artifact.type)}
                    <h3 className="font-semibold text-gray-200 text-sm">{artifact.title}</h3>
                </div>
                <div>{renderContent()}</div>
            </div>
        )
    }

    const isGlobal = artifact.type === 'GLOBAL_SUMMARY' || artifact.type === 'GLOBAL_IOC_LIST';

    return (
        <div className={`bg-sentinel-gray-dark rounded-lg border ${isGlobal ? 'border-sentinel-blue/50' : 'border-sentinel-gray-light/50'}`}>
            <div className="flex items-center justify-between p-3 border-b border-sentinel-gray-light">
                <div className="flex items-center">
                    {getIcon(artifact.type)}
                    <div>
                        <h3 className="font-semibold text-gray-200">{artifact.title}</h3>
                        {!isGlobal && (
                           <p className="text-xs text-gray-500">{artifact.type.replace(/_/g, ' ')} &bull; {t('created')}: {new Date(artifact.createdAt).toLocaleString()}</p>
                        )}
                    </div>
                </div>
                {isSplittable && (
                    <button onClick={() => onOrganize(artifact)} className="flex items-center text-sm bg-sentinel-blue/80 hover:bg-sentinel-blue text-white px-3 py-1 rounded-md transition">
                        <LightBulbIcon className="h-4 w-4 me-1" />
                        {t('organizeWithAI')}
                    </button>
                )}
            </div>
            <div>
                {renderContent()}
            </div>
        </div>
    );
};

export default ArtifactCard;
