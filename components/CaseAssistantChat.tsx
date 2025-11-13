
import React, { useState, useRef, useEffect } from 'react';
import type { ChatMessage } from '../types';
import { PaperAirplaneIcon, ShieldCheckIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

interface CaseAssistantChatProps {
    chatHistory: ChatMessage[];
    onSendMessage: (message: string) => Promise<void>;
    isLoading: boolean;
}

const CaseAssistantChat: React.FC<CaseAssistantChatProps> = ({ chatHistory, onSendMessage, isLoading }) => {
    const { t, direction } = useLocalization();
    const [message, setMessage] = useState('');
    const chatContainerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (chatContainerRef.current) {
            chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
        }
    }, [chatHistory]);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (message.trim() && !isLoading) {
            onSendMessage(message);
            setMessage('');
        }
    };

    return (
        <div className="flex flex-col h-96 bg-sentinel-gray-dark rounded-md">
            <div ref={chatContainerRef} className="flex-1 p-4 space-y-4 overflow-y-auto">
                {chatHistory.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full text-center text-gray-500">
                        <ShieldCheckIcon className="h-12 w-12 mb-2" />
                        <p className="font-semibold">{t('assistant_greeting')}</p>
                    </div>
                ) : (
                    chatHistory.map(chat => (
                        <div key={chat.id} className={`flex items-end gap-2 ${chat.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                            {chat.sender === 'ai' && <ShieldCheckIcon className="h-6 w-6 text-sentinel-blue flex-shrink-0" />}
                            <div className={`max-w-md lg:max-w-xl px-4 py-2 rounded-xl ${chat.sender === 'user' ? 'bg-sentinel-blue text-white' : 'bg-sentinel-gray-light text-gray-200'}`}>
                                <p className="text-sm whitespace-pre-wrap">{chat.text}</p>
                            </div>
                        </div>
                    ))
                )}
                 {isLoading && (
                    <div className="flex items-end gap-2 justify-start">
                        <ShieldCheckIcon className="h-6 w-6 text-sentinel-blue flex-shrink-0" />
                        <div className="max-w-md lg:max-w-xl px-4 py-2 rounded-xl bg-sentinel-gray-light text-gray-200 flex items-center space-x-1">
                            <span className="h-2 w-2 bg-gray-400 rounded-full animate-bounce delay-0"></span>
                            <span className="h-2 w-2 bg-gray-400 rounded-full animate-bounce delay-150"></span>
                            <span className="h-2 w-2 bg-gray-400 rounded-full animate-bounce delay-300"></span>
                        </div>
                    </div>
                 )}
            </div>
            <div className="p-2 border-t border-sentinel-gray-light">
                <form onSubmit={handleSubmit} className="flex items-center gap-2">
                    <input
                        type="text"
                        value={message}
                        onChange={(e) => setMessage(e.target.value)}
                        placeholder={t('chat_placeholder')}
                        className="flex-1 bg-sentinel-gray-light border-transparent focus:border-sentinel-blue focus:ring-sentinel-blue rounded-lg px-4 py-2 text-sm text-gray-200"
                        disabled={isLoading}
                    />
                    <button type="submit" disabled={isLoading || !message.trim()} className="p-2 rounded-full bg-sentinel-blue text-white disabled:bg-gray-500 transition-colors">
                        <PaperAirplaneIcon className={`h-5 w-5 ${direction === 'rtl' ? 'transform -scale-x-100' : ''}`} />
                    </button>
                </form>
            </div>
        </div>
    );
};

export default CaseAssistantChat;
