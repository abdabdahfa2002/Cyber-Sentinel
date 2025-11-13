
import React, { useState, useEffect } from 'react';
import type { ChecklistItem } from '../types';
import { ClipboardCheckIcon } from './icons';

interface ChecklistSectionProps {
  checklist: Omit<ChecklistItem, 'completed'>[];
}

const Card: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="bg-sentinel-gray-medium rounded-lg shadow-lg p-6 border border-sentinel-gray-light">
    {children}
  </div>
);

const ChecklistSection: React.FC<ChecklistSectionProps> = ({ checklist }) => {
  const [items, setItems] = useState<ChecklistItem[]>([]);
  
  useEffect(() => {
    setItems(checklist.map(item => ({...item, completed: false})));
  }, [checklist]);

  const handleToggle = (step: number) => {
    setItems(items.map(item =>
      item.step === step ? { ...item, completed: !item.completed } : item
    ));
  };
  
  const completedCount = items.filter(item => item.completed).length;
  const totalCount = items.length;
  const progress = totalCount > 0 ? (completedCount / totalCount) * 100 : 0;

  return (
    <Card>
      <div className="mb-4">
        <h2 className="text-xl font-bold text-gray-100 mb-2 flex items-center">
            <ClipboardCheckIcon className="h-6 w-6 mr-3 text-sentinel-blue" />
            Recommended Investigation Steps
        </h2>
        {/* Progress Bar */}
        <div>
            <div className="flex justify-between mb-1">
                <span className="text-base font-medium text-sentinel-blue">Progress</span>
                <span className="text-sm font-medium text-sentinel-blue">{completedCount} / {totalCount} Steps Completed</span>
            </div>
            <div className="w-full bg-sentinel-gray-dark rounded-full h-2.5">
                <div className="bg-sentinel-blue h-2.5 rounded-full" style={{width: `${progress}%`}}></div>
            </div>
        </div>
      </div>
      
      <div className="space-y-4">
        {items.map((item) => (
          <div key={item.step} className="p-4 bg-sentinel-gray-dark rounded-lg transition-all duration-300">
            <label className="flex items-start cursor-pointer">
              <input
                type="checkbox"
                checked={item.completed}
                onChange={() => handleToggle(item.step)}
                className="mt-1 h-5 w-5 rounded bg-sentinel-gray-light border-sentinel-gray-light text-sentinel-blue focus:ring-sentinel-blue"
              />
              <div className="ml-4 flex-1">
                <span className={`font-semibold text-lg ${item.completed ? 'line-through text-gray-500' : 'text-gray-200'}`}>
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
    </Card>
  );
};

export default ChecklistSection;
