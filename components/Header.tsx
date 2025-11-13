
import React from 'react';
import { ShieldCheckIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

const Header: React.FC = () => {
  const { t, setLocale, locale } = useLocalization();

  const toggleLanguage = () => {
    setLocale(locale === 'en' ? 'ar' : 'en');
  };

  return (
    <header className="bg-sentinel-gray-medium/50 backdrop-blur-sm border-b border-sentinel-gray-light sticky top-0 z-10">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex-1"></div> {/* Spacer */}
          <div className="flex items-center space-x-3 absolute left-1/2 -translate-x-1/2">
             <ShieldCheckIcon className="h-8 w-8 text-sentinel-blue" />
            <h1 className="text-2xl font-bold text-gray-100 tracking-wider">
              {t('cyberSentinel')}
            </h1>
          </div>
          <div className="flex-1 flex justify-end">
            <button
              onClick={toggleLanguage}
              className="text-sm font-medium text-gray-300 hover:text-sentinel-blue transition-colors px-3 py-2 rounded-md bg-sentinel-gray-light/50"
            >
              {locale === 'en' ? 'العربية' : 'English'}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
