

import React, { useState } from 'react';
import type { KillChainPhase, InvestigationArtifact } from '../types';
import { XCircleIcon, PencilSquareIcon, CommandLineIcon, DocumentArrowUpIcon, Cog6ToothIcon, UploadIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

interface AddArtifactModalProps {
    phase: KillChainPhase;
    onClose: () => void;
    onAddArtifact: (artifact: Omit<InvestigationArtifact, 'id' | 'createdAt'>) => void;
}

type NewArtifactType = 'ANALYST_NOTE' | 'TOOL_OUTPUT' | 'EVIDENCE_FILE' | 'TOOL_INFO';

const AddArtifactModal: React.FC<AddArtifactModalProps> = ({ phase, onClose, onAddArtifact }) => {
    const { t } = useLocalization();
    const [activeType, setActiveType] = useState<NewArtifactType>('ANALYST_NOTE');

    const ARTIFACT_TYPES: { id: NewArtifactType, label: string, Icon: React.FC<{className?: string}> }[] = [
        { id: 'ANALYST_NOTE', label: t('analystNote'), Icon: PencilSquareIcon },
        { id: 'TOOL_OUTPUT', label: t('toolOutput'), Icon: CommandLineIcon },
        { id: 'EVIDENCE_FILE', label: t('evidenceFile'), Icon: DocumentArrowUpIcon },
        { id: 'TOOL_INFO', label: t('toolInfo'), Icon: Cog6ToothIcon },
    ];

    const [noteTitle, setNoteTitle] = useState('');
    const [noteText, setNoteText] = useState('');
    
    const [toolName, setToolName] = useState('');
    const [toolCommand, setToolCommand] = useState('');
    const [toolOutput, setToolOutput] = useState('');

    const [file, setFile] = useState<File | null>(null);
    const [fileTitle, setFileTitle] = useState('');

    const [infoToolName, setInfoToolName] = useState('');
    const [infoToolVersion, setInfoToolVersion] = useState('');
    const [infoToolConfig, setInfoToolConfig] = useState('');
    
    const isNoteValid = noteTitle.trim() && noteText.trim();
    const isToolValid = toolName.trim() && toolOutput.trim();
    const isFileValid = file && fileTitle.trim();
    const isToolInfoValid = infoToolName.trim();

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        let artifact: Omit<InvestigationArtifact, 'id' | 'createdAt'> | null = null;
        
        switch (activeType) {
            case 'ANALYST_NOTE':
                if (!isNoteValid) return;
                artifact = { type: 'ANALYST_NOTE', title: noteTitle, content: { text: noteText }, killChainPhase: phase };
                break;
            case 'TOOL_OUTPUT':
                if (!isToolValid) return;
                artifact = { type: 'TOOL_OUTPUT', title: `Output: ${toolName}`, content: { toolName, command: toolCommand, output: toolOutput }, killChainPhase: phase };
                break;
            case 'TOOL_INFO':
                if (!isToolInfoValid) return;
                artifact = { type: 'TOOL_INFO', title: `Tool: ${infoToolName}`, content: { toolName: infoToolName, version: infoToolVersion, configuration: infoToolConfig }, killChainPhase: phase };
                break;
            case 'EVIDENCE_FILE':
                if (!isFileValid || !file) return;
                const reader = new FileReader();
                reader.onload = (event) => {
                    const textContent = event.target?.result as string;
                    const fileArtifact: Omit<InvestigationArtifact, 'id' | 'createdAt'> = { type: 'EVIDENCE_FILE', title: fileTitle, content: { fileName: file.name, fileType: file.type, content: textContent }, killChainPhase: phase };
                    onAddArtifact(fileArtifact);
                };
                reader.readAsText(file);
                return;
        }

        if (artifact) {
            onAddArtifact(artifact);
        }
    };

    const renderForm = () => {
        switch (activeType) {
            case 'ANALYST_NOTE':
                return (
                    <div className="space-y-4">
                        <input type="text" placeholder={t('noteTitle_placeholder')} value={noteTitle} onChange={e => setNoteTitle(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" required />
                        <textarea rows={5} placeholder={t('noteText_placeholder')} value={noteText} onChange={e => setNoteText(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" required />
                    </div>
                );
            case 'TOOL_OUTPUT':
                return (
                     <div className="space-y-4">
                        <input type="text" placeholder={t('toolName_placeholder')} value={toolName} onChange={e => setToolName(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" required />
                        <input type="text" placeholder={t('toolCommand_placeholder')} value={toolCommand} onChange={e => setToolCommand(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                        <textarea rows={8} placeholder={t('toolOutput_placeholder')} value={toolOutput} onChange={e => setToolOutput(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm font-mono text-gray-200" required />
                    </div>
                );
            case 'EVIDENCE_FILE':
                 return (
                    <div className="space-y-4">
                         <input type="text" placeholder={t('evidenceTitle_placeholder')} value={fileTitle} onChange={e => setFileTitle(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" required />
                        <div className="flex justify-center items-center w-full">
                            <label htmlFor="file-upload-artifact" className="flex flex-col justify-center items-center w-full h-32 bg-sentinel-gray-dark rounded-lg border-2 border-sentinel-gray-light border-dashed cursor-pointer hover:bg-sentinel-gray-light">
                                <div className="flex flex-col justify-center items-center pt-5 pb-6">
                                    <UploadIcon className="w-10 h-10 mb-3 text-gray-400" />
                                    {file ? (
                                        <p className="text-sm text-sentinel-green">{file.name}</p>
                                    ) : (
                                        <>
                                            <p className="mb-2 text-sm text-gray-400"><span className="font-semibold">{t('clickToUpload')}</span></p>
                                            <p className="text-xs text-gray-500">{t('textBasedFiles')}</p>
                                        </>
                                    )}
                                </div>
                                <input id="file-upload-artifact" type="file" className="hidden" accept=".txt,.csv,.log,.json,.xml" onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)} />
                            </label>
                        </div>
                    </div>
                );
            case 'TOOL_INFO':
                return (
                    <div className="space-y-4">
                        <p className="text-sm text-gray-400">{t('toolInfo_desc')}</p>
                        <input type="text" placeholder={t('toolInfoName_placeholder')} value={infoToolName} onChange={e => setInfoToolName(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" required />
                        <input type="text" placeholder={t('toolInfoVersion_placeholder')} value={infoToolVersion} onChange={e => setInfoToolVersion(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                        <textarea rows={3} placeholder={t('toolInfoConfig_placeholder')} value={infoToolConfig} onChange={e => setInfoToolConfig(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                    </div>
                );
        }
    }
    
    const isSubmitDisabled = () => {
        switch (activeType) {
            case 'ANALYST_NOTE': return !isNoteValid;
            case 'TOOL_OUTPUT': return !isToolValid;
            case 'EVIDENCE_FILE': return !isFileValid;
            case 'TOOL_INFO': return !isToolInfoValid;
            default: return true;
        }
    }

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fade-in" onClick={onClose}>
            <div className="bg-sentinel-gray-medium w-full max-w-2xl rounded-xl shadow-2xl border border-sentinel-gray-light flex flex-col" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between p-4 border-b border-sentinel-gray-light">
                    <div>
                        <h2 className="text-xl font-bold text-gray-100">{t('addArtifact')}</h2>
                        <p className="text-sm text-gray-400">{t('toPhase')}: <span className="font-semibold text-sentinel-blue">{t(phase)}</span></p>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white"><XCircleIcon className="h-8 w-8" /></button>
                </div>
                
                <form onSubmit={handleSubmit}>
                    <div className="p-6 space-y-4">
                        <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2 rounded-lg bg-sentinel-gray-dark p-1">
                            {ARTIFACT_TYPES.map(({ id, label, Icon }) => (
                                <button type="button" key={id} onClick={() => setActiveType(id)} className={`w-full flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-center transition-colors ${activeType === id ? 'bg-sentinel-blue text-white shadow' : 'text-gray-400 hover:bg-sentinel-gray-light/50'}`}>
                                    <Icon className="h-5 w-5" /> {label}
                                </button>
                            ))}
                        </div>
                        <div className="pt-4">
                            {renderForm()}
                        </div>
                    </div>
                    <div className="p-4 bg-sentinel-gray-dark/50 border-t border-sentinel-gray-light flex justify-end gap-3 rounded-b-xl">
                        <button type="button" onClick={onClose} className="px-4 py-2 text-sm rounded-md bg-sentinel-gray-light hover:bg-gray-600">{t('cancel')}</button>
                        <button type="submit" disabled={isSubmitDisabled()} className="px-4 py-2 text-sm rounded-md bg-sentinel-blue hover:bg-cyan-600 text-white disabled:opacity-50 disabled:cursor-not-allowed">{t('addToCase')}</button>
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

export default AddArtifactModal;