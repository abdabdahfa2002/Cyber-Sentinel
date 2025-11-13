// We use a free, public API that provides both parsing and security-related flags.
// This service does not require an API key.
const PARSER_API_URL = 'https://corsproxy.io/?https://evil-ua.com/api/v1/ua/';

export const parseUserAgent = async (userAgent: string): Promise<any> => {
    const targetUrl = `${PARSER_API_URL}${encodeURIComponent(userAgent)}`;
  
    const response = await fetch(targetUrl, {
        method: 'GET',
    });

    if (!response.ok) {
        try {
            const errorData = await response.json();
            throw new Error(errorData.message || `API Error: ${response.statusText}`);
        } catch (e) {
            throw new Error(`User-Agent parser returned status ${response.status}.`);
        }
    }

    const data = await response.json();
    return data;
}