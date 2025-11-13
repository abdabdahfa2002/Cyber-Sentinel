

import React, { useState } from 'react';
import type { NewCaseDetails } from '../types';
import { XCircleIcon, BriefcaseIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

interface CreateCaseModalProps {
    onClose: () => void;
    onCreateCase: (details: NewCaseDetails) => void;
}

const CreateCaseModal: React.FC<CreateCaseModalProps> = ({ onClose, onCreateCase }) => {
    const { t } = useLocalization();
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [summary, setSummary] = useState('');
    const [notes, setNotes] = useState('');
    const [toolName, setToolName] = useState('');
    const [toolVersion, setToolVersion] = useState('');
    const [toolConfig, setToolConfig] = useState('');

    const isFormValid = name.trim() !== '' && description.trim() !== '';

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!isFormValid) return;
        onCreateCase({
            name,
            description,
            summary,
            notes,
            toolName,
            toolVersion,
            toolConfig,
        });
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fade-in" onClick={onClose}>
            <div className="bg-sentinel-gray-medium w-full max-w-2xl rounded-xl shadow-2xl border border-sentinel-gray-light flex flex-col" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between p-4 border-b border-sentinel-gray-light">
                    <h2 className="text-xl font-bold text-gray-100 flex items-center">
                        <BriefcaseIcon className="h-6 w-6 me-3 text-sentinel-blue" />
                        {t('createNewCase')}
                    </h2>
                    <button onClick={onClose} className="text-gray-400 hover:text-white"><XCircleIcon className="h-8 w-8" /></button>
                </div>
                
                <form onSubmit={handleSubmit}>
                    <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
                        {/* Basic Info */}
                        <fieldset className="border border-sentinel-gray-light p-4 rounded-lg">
                            <legend className="px-2 text-sm font-semibold text-sentinel-blue">{t('basicInfo')}</legend>
                            <div className="space-y-4">
                                <div>
                                    <label htmlFor="case-name" className="block text-sm font-medium text-gray-300 mb-1">{t('caseName')}*</label>
                                    <input id="case-name" type="text" value={name} onChange={e => setName(e.target.value)} placeholder={t('caseName_placeholder')} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" required />
                                </div>
                                <div>
                                    <label htmlFor="case-description" className="block text-sm font-medium text-gray-300 mb-1">{t('description')}*</label>
                                    <textarea id="case-description" rows={2} value={description} onChange={e => setDescription(e.target.value)} placeholder={t('description_placeholder')} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" required />
                                </div>
                            </div>
                        </fieldset>

                        {/* Initial Findings */}
                        <fieldset className="border border-sentinel-gray-light p-4 rounded-lg">
                            <legend className="px-2 text-sm font-semibold text-sentinel-blue">{t('initialFindings')}</legend>
                            <div className="space-y-4">
                                <div>
                                    <label htmlFor="case-summary" className="block text-sm font-medium text-gray-300 mb-1">{t('incidentSummary')}</label>
                                    <textarea id="case-summary" rows={3} value={summary} onChange={e => setSummary(e.target.value)} placeholder={t('incidentSummary_placeholder')} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                                </div>
                                <div>
                                    <label htmlFor="case-notes" className="block text-sm font-medium text-gray-300 mb-1">{t('preliminaryNotes')}</label>
                                    <textarea id="case-notes" rows={3} value={notes} onChange={e => setNotes(e.target.value)} placeholder={t('preliminaryNotes_placeholder')} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                                </div>
                            </div>
                        </fieldset>
                        
                        {/* Tooling Context */}
                        <fieldset className="border border-sentinel-gray-light p-4 rounded-lg">
                            <legend className="px-2 text-sm font-semibold text-sentinel-blue">{t('toolingContext')}</legend>
                             <div className="space-y-4">
                                <div>
                                    <label htmlFor="tool-name" className="block text-sm font-medium text-gray-300 mb-1">{t('toolInfoName_placeholder')}</label>
                                    <input id="tool-name" type="text" value={toolName} onChange={e => setToolName(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                                </div>
                                <div>
                                    <label htmlFor="tool-version" className="block text-sm font-medium text-gray-300 mb-1">{t('toolInfoVersion_placeholder')}</label>
                                    <input id="tool-version" type="text" value={toolVersion} onChange={e => setToolVersion(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                                </div>
                                <div>
                                    <label htmlFor="tool-config" className="block text-sm font-medium text-gray-300 mb-1">{t('toolInfoConfig_placeholder')}</label>
                                    <textarea id="tool-config" rows={2} value={toolConfig} onChange={e => setToolConfig(e.target.value)} className="w-full bg-sentinel-gray-dark border border-sentinel-gray-light rounded-md p-2 text-sm text-gray-200" />
                                </div>
                            </div>
                        </fieldset>
                    </div>

                    <div className="p-4 bg-sentinel-gray-dark/50 border-t border-sentinel-gray-light flex justify-end gap-3 rounded-b-xl">
                        <button type="button" onClick={onClose} className="px-4 py-2 text-sm rounded-md bg-sentinel-gray-light hover:bg-gray-600">{t('cancel')}</button>
                        <button type="submit" disabled={!isFormValid} className="px-4 py-2 text-sm rounded-md bg-sentinel-blue hover:bg-cyan-600 text-white disabled:opacity-50">{t('createCase')}</button>
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

export default CreateCaseModal;