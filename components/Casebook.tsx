

import React, { useState } from 'react';
import type { Case, NewCaseDetails } from '../types';
import { BriefcaseIcon, ChevronRightIcon, FolderOpenIcon, PlusIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';
import CreateCaseModal from './CreateCaseModal';

interface CasebookProps {
    cases: Case[];
    onSelectCase: (id: string | null) => void;
    onCreateCase: (details: NewCaseDetails) => void;
}

const Casebook: React.FC<CasebookProps> = ({ cases, onSelectCase, onCreateCase }) => {
    const { t } = useLocalization();
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

    const handleCreateAndClose = (details: NewCaseDetails) => {
        onCreateCase(details);
        setIsCreateModalOpen(false);
    };

    return (
        <>
            {isCreateModalOpen && <CreateCaseModal onClose={() => setIsCreateModalOpen(false)} onCreateCase={handleCreateAndClose} />}
            <div className="bg-sentinel-gray-medium rounded-lg shadow-xl border border-sentinel-gray-light p-6 animate-fade-in">
                <div className="flex flex-col sm:flex-row justify-between items-center mb-6 gap-4">
                    <h1 className="text-2xl font-bold text-gray-100 flex items-center">
                        <BriefcaseIcon className="h-7 w-7 me-3 text-sentinel-blue" />
                        {t('investigationCasebook')}
                    </h1>
                    <button
                        onClick={() => setIsCreateModalOpen(true)}
                        className="w-full sm:w-auto flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-sentinel-blue hover:bg-cyan-600"
                    >
                        <PlusIcon className="h-5 w-5 me-2" />
                        {t('createNewCase')}
                    </button>
                </div>

                <h2 className="text-lg font-semibold text-gray-200 mb-3 mt-8">{t('openCases')}</h2>
                {cases.length === 0 ? (
                    <div className="text-center py-16 border-2 border-dashed border-sentinel-gray-light rounded-lg">
                        <FolderOpenIcon className="mx-auto h-12 w-12 text-gray-500" />
                        <h3 className="mt-2 text-sm font-semibold text-gray-300">{t('noCasesFound')}</h3>
                        <p className="mt-1 text-sm text-gray-500">{t('createFirstCase')}</p>
                    </div>
                ) : (
                    <div className="space-y-3">
                        {cases.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).map(c => (
                            <div 
                                key={c.id} 
                                onClick={() => onSelectCase(c.id)}
                                className="bg-sentinel-gray-dark p-4 rounded-lg flex items-center justify-between transition-all duration-200 hover:bg-sentinel-gray-light cursor-pointer border border-transparent hover:border-sentinel-blue shadow-sm"
                            >
                                <div>
                                    <p className="font-semibold text-gray-200">{c.name}</p>
                                    <p className="text-sm text-gray-400 truncate max-w-lg">{c.description || t('noDescription')}</p>
                                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                                      <span>{t('created')}: {new Date(c.createdAt).toLocaleString()}</span>
                                      <span className={`px-2 py-0.5 rounded-full text-white font-semibold ${c.status === 'Closed' ? 'bg-gray-500' : c.status === 'In Progress' ? 'bg-yellow-600' : 'bg-green-600'}`}>
                                        {c.status}
                                      </span>
                                    </div>
                                </div>
                                <ChevronRightIcon className="h-6 w-6 text-gray-500 flex-shrink-0 ms-4" />
                            </div>
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
        </>
    );
};

export default Casebook;