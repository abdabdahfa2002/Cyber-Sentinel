
import React from 'react';
import type { TimelineEvent } from '../types';
import { ClockIcon } from './icons';

interface TimelineSectionProps {
  events: TimelineEvent[];
}

const Card: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="bg-sentinel-gray-medium rounded-lg shadow-lg p-6 border border-sentinel-gray-light">
    {children}
  </div>
);

const TimelineSection: React.FC<TimelineSectionProps> = ({ events }) => {
  return (
    <Card>
      <h2 className="text-xl font-bold text-gray-100 mb-6 flex items-center">
        <ClockIcon className="h-6 w-6 mr-3 text-sentinel-blue" />
        Attack Timeline
      </h2>
      <div className="relative border-l-2 border-sentinel-gray-light ml-3">
        {events.map((event, index) => (
          <div key={index} className="mb-8 ml-8">
            <span className="absolute flex items-center justify-center w-6 h-6 bg-sentinel-blue rounded-full -left-3 ring-8 ring-sentinel-gray-medium">
                <svg className="w-2.5 h-2.5 text-cyan-200" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M20 4a2 2 0 0 0-2-2h-2V1a1 1 0 0 0-2 0v1h-3V1a1 1 0 0 0-2 0v1H6V1a1 1 0 0 0-2 0v1H2a2 2 0 0 0-2 2v2h20V4Z"/>
                </svg>
            </span>
            <div className="p-4 bg-sentinel-gray-dark rounded-lg border border-sentinel-gray-light shadow-sm">
                <time className="text-sm font-normal leading-none text-gray-400">{event.timestamp}</time>
                <p className="mt-2 text-base font-normal text-gray-300">{event.event}</p>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
};

export default TimelineSection;
