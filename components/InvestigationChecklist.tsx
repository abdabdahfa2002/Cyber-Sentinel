
import React from 'react';
import type { ChecklistItem } from '../types';
import { useLocalization } from '../contexts/LocalizationContext';

interface InvestigationChecklistProps {
  items: ChecklistItem[];
  onToggleItem: (step: number) => void;
}

const InvestigationChecklist: React.FC<InvestigationChecklistProps> = ({ items, onToggleItem }) => {
  const { t } = useLocalization();

  if (!items || items.length === 0) {
    return <p className="text-center text-gray-500 py-4">{t('noInvestigationSteps')}</p>;
  }

  const completedCount = items.filter(item => item.completed).length;
  const totalCount = items.length;
  const progress = totalCount > 0 ? (completedCount / totalCount) * 100 : 0;

  return (
    <div className="space-y-4">
      <div>
        <div className="flex justify-between mb-1">
          <span className="text-base font-medium text-sentinel-blue">{t('overallProgress')}</span>
          <span className="text-sm font-medium text-sentinel-blue">{t('stepsCompleted', { completed: completedCount, total: totalCount })}</span>
        </div>
        <div className="w-full bg-sentinel-gray-dark rounded-full h-2.5">
          <div className="bg-sentinel-blue h-2.5 rounded-full transition-all duration-500" style={{ width: `${progress}%` }}></div>
        </div>
      </div>
      
      <div className="space-y-3 max-h-60 overflow-y-auto pe-2">
        {items.map((item) => (
          <div key={item.step} className="p-3 bg-sentinel-gray-dark rounded-lg">
            <label className="flex items-start cursor-pointer">
              <input
                type="checkbox"
                checked={item.completed}
                onChange={() => onToggleItem(item.step)}
                className="mt-1 h-5 w-5 rounded bg-sentinel-gray-light border-sentinel-gray-light text-sentinel-blue focus:ring-sentinel-blue"
              />
              <div className="ms-4 flex-1">
                <span className={`font-semibold text-md ${item.completed ? 'line-through text-gray-500' : 'text-gray-200'}`}>
                  {item.action}
                </span>
                <p className={`mt-1 text-sm ${item.completed ? 'text-gray-600' : 'text-gray-400'}`}>
                  {item.details}
                </p>
              </div>
            </label>
          </div>
        ))}
      </div>
    </div>
  );
};

export default InvestigationChecklist;
