
import React, { useState } from 'react';
import type { Case, InvestigationArtifact, KillChainPhase, ChecklistItem, ChatMessage } from '../types';
import { suggestNextSteps, SplitArtifactResult } from '../services/geminiService';
import { ArrowLeftIcon, BrainIcon, PlusIcon, LightBulbIcon, Cog6ToothIcon, InboxStackIcon, FolderOpenIcon, ListBulletIcon, DocumentTextIcon, ChatBubbleLeftRightIcon } from './icons';
import ArtifactCard from './ArtifactCard';
import AddArtifactModal from './AddArtifactModal';
import SplitArtifactModal from './SplitArtifactModal';
import InvestigationChecklist from './InvestigationChecklist';
import CaseAssistantChat from './CaseAssistantChat';
import { useLocalization } from '../contexts/LocalizationContext';

interface CaseDetailViewProps {
    caseData: Case;
    onBack: () => void;
    onAddArtifact: (artifact: Omit<InvestigationArtifact, 'id' | 'createdAt'>) => void;
    onUpdateArtifact: (artifactId: string, updates: Partial<InvestigationArtifact>) => void;
    onUpdateChecklist: (newChecklist: Omit<ChecklistItem, 'completed'>[]) => void;
    onToggleChecklistItem: (step: number) => void;
    onStartNewAnalysis: () => void;
    onSplitAndOrganizeArtifact: (originalArtifactId: string, newArtifactsData: SplitArtifactResult[]) => void;
    onSendMessage: (message: string) => Promise<void>;
    isChatLoading: boolean;
}

const KILL_CHAIN_PHASES: KillChainPhase[] = ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Command and Control', 'Actions on Objectives'];

const Section: React.FC<{ title: React.ReactNode; icon: React.ReactNode; children: React.ReactNode; actionButton?: React.ReactNode; }> = ({ title, icon, children, actionButton }) => (
    <div className="bg-sentinel-gray-medium rounded-lg shadow-lg border border-sentinel-gray-light p-4">
        <div className="flex justify-between items-center mb-3 border-b border-sentinel-gray-light pb-2">
            <h2 className="text-xl font-semibold text-gray-200 flex items-center">
                {icon} {title}
            </h2>
            {actionButton}
        </div>
        {children}
    </div>
);

const CaseDetailView: React.FC<CaseDetailViewProps> = (props) => {
    const { t } = useLocalization();
    const { caseData, onBack, onAddArtifact, onUpdateChecklist, onToggleChecklistItem, onStartNewAnalysis, onSplitAndOrganizeArtifact, onSendMessage, isChatLoading } = props;
    const [isAddModalOpen, setIsAddModalOpen] = useState(false);
    const [isSplitModalOpen, setIsSplitModalOpen] = useState(false);
    const [selectedPhase, setSelectedPhase] = useState<KillChainPhase | null>(null);
    const [artifactToOrganize, setArtifactToOrganize] = useState<InvestigationArtifact | null>(null);
    const [isSuggestingSteps, setIsSuggestingSteps] = useState(false);

    const handleOpenAddModal = (phase: KillChainPhase) => {
        setSelectedPhase(phase);
        setIsAddModalOpen(true);
    };
    
    const handleOpenSplitModal = (artifact: InvestigationArtifact) => {
        setArtifactToOrganize(artifact);
        setIsSplitModalOpen(true);
    };

    const handleAddArtifactAndClose = (artifact: Omit<InvestigationArtifact, 'id' | 'createdAt'>) => {
        onAddArtifact(artifact);
        setIsAddModalOpen(false);
    };

    const handleSuggestNextSteps = async () => {
        setIsSuggestingSteps(true);
        const caseContext = `
            Case Name: ${caseData.name}
            Description: ${caseData.description}
            --- ARTIFACTS ---
            ${JSON.stringify(caseData.artifacts, null, 2)}
        `;
        try {
            const steps = await suggestNextSteps(caseContext);
            onUpdateChecklist(steps);
        } catch (error) {
            console.error("Failed to suggest next steps:", error);
        } finally {
            setIsSuggestingSteps(false);
        }
    };
    
    const handleConfirmSplit = (newArtifactsData: SplitArtifactResult[]) => {
        if (artifactToOrganize) {
            onSplitAndOrganizeArtifact(artifactToOrganize.id, newArtifactsData);
        }
        setIsSplitModalOpen(false);
        setArtifactToOrganize(null);
    };

    const uncategorizedArtifacts = caseData.artifacts.filter(a => a.killChainPhase === 'Uncategorized');
    const toolInfoArtifacts = uncategorizedArtifacts.filter(a => a.type === 'TOOL_INFO');
    const inboxArtifacts = uncategorizedArtifacts.filter(a => a.type !== 'TOOL_INFO' && a.type !== 'GLOBAL_SUMMARY' && a.type !== 'GLOBAL_IOC_LIST');

    const globalSummary = caseData.artifacts.find(a => a.type === 'GLOBAL_SUMMARY');
    const globalIoCs = caseData.artifacts.find(a => a.type === 'GLOBAL_IOC_LIST');

    return (
        <>
            {isAddModalOpen && selectedPhase && (
                <AddArtifactModal phase={selectedPhase} onClose={() => setIsAddModalOpen(false)} onAddArtifact={handleAddArtifactAndClose} />
            )}
            {isSplitModalOpen && artifactToOrganize && (
                <SplitArtifactModal artifact={artifactToOrganize} onClose={() => setIsSplitModalOpen(false)} onConfirmSplit={handleConfirmSplit} />
            )}

            <div className="animate-fade-in space-y-6">
                <div>
                    <button onClick={onBack} className="flex items-center text-sm text-sentinel-blue hover:text-cyan-400 mb-2 transition-colors">
                        <ArrowLeftIcon className="h-4 w-4 me-2" /> {t('backToCasebook')}
                    </button>
                    <h1 className="text-3xl font-bold text-gray-100">{caseData.name}</h1>
                    <p className="text-gray-400 max-w-2xl mt-1">{caseData.description}</p>
                </div>

                <Section
                    title={t('caseAssistant')}
                    icon={<ChatBubbleLeftRightIcon className="h-6 w-6 me-3 text-sentinel-blue" />}
                >
                    <CaseAssistantChat
                        chatHistory={caseData.chatHistory}
                        onSendMessage={onSendMessage}
                        isLoading={isChatLoading}
                    />
                </Section>
                
                <Section 
                    title={t('caseIntelligenceBriefing')}
                    icon={<BrainIcon className="h-6 w-6 me-3 text-sentinel-blue" />}
                >
                    <div className="space-y-4">
                        {globalSummary ? <ArtifactCard artifact={globalSummary} /> : <p className="text-sm text-gray-500">{t('globalSummaryGenerating')}</p>}
                        {globalIoCs ? <ArtifactCard artifact={globalIoCs} /> : <p className="text-sm text-gray-500">{t('globalIoCGenerating')}</p>}
                    </div>
                </Section>
                
                <Section 
                    title={t('investigationPlan')} 
                    icon={<LightBulbIcon className="h-6 w-6 me-3 text-sentinel-blue" />}
                    actionButton={
                        <button onClick={handleSuggestNextSteps} disabled={isSuggestingSteps} className="flex items-center text-sm bg-sentinel-blue/80 hover:bg-sentinel-blue text-white px-3 py-1 rounded-md transition disabled:opacity-50">
                             {isSuggestingSteps ? (
                                <>
                                    <svg className="animate-spin -ms-1 me-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    {t('thinking')}
                                </>
                             ) : t('suggestNextSteps') }
                        </button>
                    }
                >
                    <InvestigationChecklist items={caseData.investigationChecklist} onToggleItem={onToggleChecklistItem} />
                </Section>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <Section title={t('investigationContext')} icon={<Cog6ToothIcon className="h-6 w-6 me-3 text-sentinel-blue" />} actionButton={<button onClick={() => handleOpenAddModal('Uncategorized')} className="flex items-center text-sm bg-sentinel-gray-dark hover:bg-sentinel-gray-light text-white px-3 py-1 rounded-md transition"><PlusIcon className="h-4 w-4 me-1" /> {t('addToolInfo')}</button>}>
                        {toolInfoArtifacts.length > 0 ? (
                             <div className="space-y-2">
                                {toolInfoArtifacts.map(artifact => <ArtifactCard key={artifact.id} artifact={artifact} />)}
                            </div>
                        ) : <p className="text-sm text-gray-500 text-center py-4">{t('noToolsLogged')}</p>}
                    </Section>
                    
                    <Section title={t('analystInbox')} icon={<InboxStackIcon className="h-6 w-6 me-3 text-sentinel-blue" />} actionButton={<button onClick={() => handleOpenAddModal('Uncategorized')} className="flex items-center text-sm bg-sentinel-gray-dark hover:bg-sentinel-gray-light text-white px-3 py-1 rounded-md transition"><PlusIcon className="h-4 w-4 me-1" /> {t('addToInbox')}</button>}>
                        {inboxArtifacts.length > 0 ? (
                             <div className="space-y-2 max-h-60 overflow-y-auto pe-2">
                                {inboxArtifacts.map(artifact => <ArtifactCard key={artifact.id} artifact={artifact} onOrganize={handleOpenSplitModal} />)}
                            </div>
                        ) : <p className="text-sm text-gray-500 text-center py-4">{t('inboxIsClear')}</p>}
                    </Section>
                </div>


                <div className="space-y-4">
                    <div className="text-center">
                        <button onClick={onStartNewAnalysis} className="flex-shrink-0 w-full flex items-center justify-center px-4 py-2 border-2 border-dashed border-sentinel-gray-light hover:border-sentinel-blue hover:bg-sentinel-gray-light rounded-lg text-gray-300 transition">
                            <BrainIcon className="h-5 w-5 me-2 text-sentinel-blue" /> {t('runNewAIAnalysis')}
                        </button>
                    </div>
                    {KILL_CHAIN_PHASES.map(phase => {
                        const phaseArtifacts = caseData.artifacts.filter(a => a.killChainPhase === phase);
                        const phaseIndex = phaseArtifacts.find(a => a.type === 'CASE_INDEX');
                        const otherArtifacts = phaseArtifacts.filter(a => a.type !== 'CASE_INDEX');
                        const hasArtifacts = otherArtifacts.length > 0;

                        const phaseTitle = (
                            <span className="flex items-center gap-2">
                                {t(phase)}
                                {hasArtifacts && (
                                    <span 
                                        className="h-2.5 w-2.5 rounded-full bg-sentinel-green"
                                        title={t('phaseContainsArtifacts', { count: otherArtifacts.length })}
                                    ></span>
                                )}
                                <span className="text-base font-normal text-gray-500">({otherArtifacts.length})</span>
                            </span>
                        );

                        return (
                            <Section key={phase} title={phaseTitle} icon={<div className="w-6 h-6 me-3"></div>} actionButton={<button onClick={() => handleOpenAddModal(phase)} className="flex items-center text-sm bg-sentinel-gray-dark hover:bg-sentinel-gray-light text-white px-3 py-1 rounded-md transition"><PlusIcon className="h-4 w-4 me-1" /> {t('addArtifact')}</button>}>
                               {phaseIndex && <ArtifactCard artifact={phaseIndex} />}
                               {otherArtifacts.length > 0 ? (
                                   <div className="space-y-4 pt-2">
                                       {otherArtifacts.map(artifact => <ArtifactCard key={artifact.id} artifact={artifact} />)}
                                   </div>
                               ) : !phaseIndex ? (
                                   <div className="text-center py-6 border-2 border-dashed border-sentinel-gray-light rounded-lg">
                                       <FolderOpenIcon className="mx-auto h-8 w-8 text-gray-600" />
                                       <p className="mt-2 text-sm text-gray-500">{t('noArtifactsForPhase')}</p>
                                   </div>
                               ) : null}
                           </Section>
                        );
                    })}
                </div>

                <style>{` @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } } .animate-fade-in { animation: fade-in 0.3s ease-out forwards; } `}</style>
            </div>
        </>
    );
};

export default CaseDetailView;