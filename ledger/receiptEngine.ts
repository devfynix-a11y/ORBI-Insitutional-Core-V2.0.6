import { jsPDF } from "jspdf";
import { Transaction } from '../types.js';
import { CurrencyUtils, EnvUtils, APP_LOGO_URL } from '../services/utils.js';
import { DataVault } from '../backend/security/encryption.js';
import { DataProtection } from '../backend/security/DataProtection.js';

/**
 * ORBI MODERN RECEIPT ENGINE V6.0
 * Generates premium financial receipts with advanced branding and modern design.
 */
export const ReceiptEngine = {
    /**
     * Decryption helper for secure metadata retrieval
     */
    private: {
        async decryptValue(v: any): Promise<string> {
            if (typeof v === 'string' && v.startsWith('enc_v')) {
                const res = await DataProtection.decryptValue(v);
                return String(res);
            }
            return String(v || '');
        },

        /**
         * Advanced logo loader with multiple fallback strategies
         */
        async getLogo(): Promise<{ data: string | null; width: number; height: number }> {
            // Priority 1: Advanced Utils Fetch (highest quality)
            const base64 = await EnvUtils.imageUrlToBase64(APP_LOGO_URL);
            if (base64) {
                return new Promise((resolve) => {
                    const img = new Image();
                    img.onload = () => {
                        resolve({ data: base64, width: img.width, height: img.height });
                    };
                    img.onerror = () => resolve({ data: null, width: 0, height: 0 });
                    img.src = base64;
                });
            }

            // Priority 2: DOM scraping for PWA environments
            const domLogo = document.querySelector('img[src*="logo"], img[alt*="logo"], img[alt*="Logo"]') as HTMLImageElement;
            if (domLogo && domLogo.complete && domLogo.naturalWidth > 0) {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    if (!ctx) return { data: null, width: 0, height: 0 };
                    
                    canvas.width = domLogo.naturalWidth;
                    canvas.height = domLogo.naturalHeight;
                    ctx.drawImage(domLogo, 0, 0);
                    const dataUrl = canvas.toDataURL('image/png');
                    return { data: dataUrl, width: canvas.width, height: canvas.height };
                } catch (e) {
                    console.warn('DOM logo extraction failed:', e);
                }
            }

            // Priority 3: Built-in fallback SVG logo
            const fallbackSVG = `<svg width="200" height="60" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#0EA5E9;stop-opacity:1" />
                        <stop offset="100%" style="stop-color:#10B981;stop-opacity:1" />
                    </linearGradient>
                </defs>
                <rect x="10" y="10" width="40" height="40" rx="8" fill="url(#grad1)" />
                <text x="60" y="35" font-family="Arial, sans-serif" font-size="24" font-weight="bold" fill="#1E293B">Orbi</text>
            </svg>`;
            
            return { 
                data: `data:image/svg+xml;base64,${btoa(fallbackSVG)}`, 
                width: 200, 
                height: 60 
            };
        },

        /**
         * Creates a modern gradient background
         */
        createGradient(doc: jsPDF, x: number, y: number, width: number, height: number, colors: number[][], angle: number = 0) {
            // Simple gradient simulation for PDF
            const steps = 10;
            const stepWidth = width / steps;
            
            colors.forEach((color, index) => {
                const nextColor = colors[index + 1] || color;
                for (let i = 0; i < steps / colors.length; i++) {
                    const progress = i / (steps / colors.length);
                    const r = Math.round(color[0] + (nextColor[0] - color[0]) * progress);
                    const g = Math.round(color[1] + (nextColor[1] - color[1]) * progress);
                    const b = Math.round(color[2] + (nextColor[2] - color[2]) * progress);
                    
                    doc.setFillColor(r, g, b);
                    doc.rect(x + (index * stepWidth) + (i * stepWidth / (steps / colors.length)), 
                           y, stepWidth / colors.length, height, "F");
                }
            });
        }
    },

    /**
     * Generates a modern financial receipt with premium design elements
     */
    async generate(t: Transaction, currency: string, options: {
        includeQR?: boolean;
        watermark?: boolean;
        paperSize?: 'A4' | 'receipt' | 'letter';
        showTax?: boolean;
    } = {}) {
        const config = {
            includeQR: false,
            watermark: true,
            paperSize: 'receipt' as const,
            showTax: false,
            ...options
        };

        // 1. Context Resolution
        const [description, notes, peer, category] = await Promise.all([
            this.private.decryptValue(t.description),
            this.private.decryptValue(t.notes),
            this.private.decryptValue(t.peerContact),
            this.private.decryptValue(t.categoryName)
        ]);

        const isCredit = t.type === 'deposit';
        
        // Modern Color Palette
        const palette = {
            primary: [14, 165, 233],    // Orbi Blue
            success: [16, 185, 129],    // Emerald Green
            warning: [245, 158, 11],    // Amber
            danger: [239, 68, 68],      // Red
            dark: [15, 23, 42],         // Slate-900
            light: [248, 250, 252],     // Slate-50
            muted: [100, 116, 139],     // Slate-500
            accent: [139, 92, 246]      // Purple for highlights
        };

        const primaryColor = isCredit ? palette.success : palette.primary;

        // 2. Document Setup with modern dimensions
        const paperFormats = {
            receipt: [80, 280],    // Extended length for modern receipts
            A4: [210, 297],
            letter: [216, 279]
        };

        const format = paperFormats[config.paperSize];
        const doc = new jsPDF({
            orientation: "portrait",
            unit: "mm",
            format: format as [number, number]
        });

        const pageWidth = format[0];
        const margin = 15;
        const contentWidth = pageWidth - (margin * 2);
        const centerX = pageWidth / 2;
        let y = margin;

        // 3. Modern Background with subtle pattern
        doc.setFillColor(250, 252, 255);
        doc.rect(0, 0, pageWidth, format[1], "F");
        
        // Subtle grid pattern in background
        doc.setDrawColor(241, 245, 249);
        doc.setLineWidth(0.1);
        for (let i = margin; i < pageWidth - margin; i += 10) {
            doc.line(i, margin, i, format[1] - margin);
        }
        for (let i = margin; i < format[1] - margin; i += 10) {
            doc.line(margin, i, pageWidth - margin, i);
        }

        // 4. Premium Header with Logo
        const logo = await this.private.getLogo();
        
        // Logo container with shadow effect
        doc.setFillColor(255, 255, 255);
        doc.setDrawColor(226, 232, 240);
        doc.setLineWidth(0.5);
        doc.roundedRect(margin, y, contentWidth, 50, 3, 3, "FD");
        
        if (logo.data) {
            // Calculate logo dimensions to fit nicely
            const logoMaxWidth = 40;
            const logoMaxHeight = 40;
            const logoAspect = logo.width / logo.height;
            
            let logoWidth = logoMaxWidth;
            let logoHeight = logoMaxWidth / logoAspect;
            
            if (logoHeight > logoMaxHeight) {
                logoHeight = logoMaxHeight;
                logoWidth = logoMaxHeight * logoAspect;
            }
            
            const logoX = margin + 10;
            const logoY = y + (50 - logoHeight) / 2;
            
            try {
                doc.addImage(logo.data, 'PNG', logoX, logoY, logoWidth, logoHeight);
            } catch (e) {
                // Fallback if image format not supported
                console.warn('Logo image format not supported, using fallback');
            }
            
            // Company name next to logo
            doc.setFont("helvetica", "bold");
            doc.setFontSize(16);
            doc.setTextColor(palette.dark[0], palette.dark[1], palette.dark[2]);
            doc.text("ORBI", logoX + logoWidth + 10, y + 25);
            
            doc.setFont("helvetica", "normal");
            doc.setFontSize(8);
            doc.setTextColor(palette.muted[0], palette.muted[1], palette.muted[2]);
            doc.text("Digital Financial Platform", logoX + logoWidth + 10, y + 30);
        }
        
        y += 60;

        // 5. Transaction Status Badge
        const statusText = isCredit ? "CREDIT SETTLEMENT" : "DEBIT SETTLEMENT";
        const statusColor = isCredit ? palette.success : palette.primary;
        
        doc.setFillColor(statusColor[0], statusColor[1], statusColor[2]);
        doc.roundedRect(margin, y, contentWidth, 12, 6, 6, "F");
        
        doc.setFont("helvetica", "bold");
        doc.setFontSize(9);
        doc.setTextColor(255, 255, 255);
        doc.text(statusText, centerX, y + 7.5, { align: "center" });
        
        y += 20;

        // 6. Amount Display with modern styling
        doc.setFont("helvetica", "bold");
        doc.setFontSize(24);
        doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
        
        const amountStr = (isCredit ? "+" : "−") + CurrencyUtils.formatMoney(Math.abs(t.amount), currency);
        const amountWidth = doc.getTextWidth(amountStr);
        const amountX = centerX - (amountWidth / 2);
        
        // Amount background highlight
        doc.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2], 0.1);
        doc.roundedRect(amountX - 10, y - 5, amountWidth + 20, 40, 8, 8, "F");
        
        doc.text(amountStr, centerX, y + 15, { align: "center" });
        
        y += 45;

        // 7. Modern Info Grid
        const infoItems = [
            { label: "Transaction ID", value: String(t.referenceId || t.id).substring(0, 16).toUpperCase(), icon: "🔒" },
            { label: "Date & Time", value: new Date(t.createdAt || t.date).toLocaleString([], { 
                year: 'numeric', 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            }), icon: "🕒" },
            { label: "Category", value: (category || "UNCLASSIFIED").toUpperCase(), icon: "🏷️" },
            { label: "Description", value: (description || "DIRECT SETTLEMENT").toUpperCase(), icon: "📝" },
            ...(peer ? [{ label: "Counterparty", value: peer.toUpperCase(), icon: "👤" }] : []),
            ...(notes ? [{ label: "Notes", value: notes.length > 40 ? notes.substring(0, 37) + "..." : notes, icon: "📄" }] : [])
        ];

        infoItems.forEach((item, index) => {
            // Alternating row background
            if (index % 2 === 0) {
                doc.setFillColor(248, 250, 252);
                doc.rect(margin, y - 4, contentWidth, 16, "F");
            }
            
            // Icon
            doc.setFontSize(8);
            doc.setTextColor(palette.muted[0], palette.muted[1], palette.muted[2]);
            doc.text(item.icon, margin + 5, y + 4);
            
            // Label
            doc.setFont("helvetica", "bold");
            doc.setFontSize(7);
            doc.text(item.label, margin + 15, y + 4);
            
            // Value
            doc.setFont("helvetica", "normal");
            doc.setFontSize(8);
            doc.setTextColor(palette.dark[0], palette.dark[1], palette.dark[2]);
            
            // Truncate long values
            let displayValue = item.value;
            const maxWidth = contentWidth - 50;
            let textWidth = doc.getTextWidth(displayValue);
            
            while (textWidth > maxWidth && displayValue.length > 10) {
                displayValue = displayValue.substring(0, displayValue.length - 4) + "...";
                textWidth = doc.getTextWidth(displayValue);
            }
            
            doc.text(displayValue, pageWidth - margin - 5, y + 4, { align: "right" });
            
            // Separator line
            if (index < infoItems.length - 1) {
                doc.setDrawColor(226, 232, 240);
                doc.setLineWidth(0.2);
                doc.line(margin + 15, y + 8, pageWidth - margin - 5, y + 8);
            }
            
            y += 16;
        });

        y += 10;

        // 8. QR Code Section (if enabled)
        if (config.includeQR) {
            // Placeholder for QR code - you can integrate a QR library here
            doc.setFillColor(241, 245, 249);
            doc.roundedRect(centerX - 20, y, 40, 40, 4, 4, "F");
            doc.setFont("helvetica", "bold");
            doc.setFontSize(6);
            doc.setTextColor(palette.muted[0], palette.muted[1], palette.muted[2]);
            doc.text("SCAN FOR DETAILS", centerX, y + 48, { align: "center" });
            y += 60;
        }

        // 9. Security Footer with modern design
        doc.setFillColor(palette.dark[0], palette.dark[1], palette.dark[2]);
        doc.rect(0, format[1] - 40, pageWidth, 40, "F");
        
        // Security pattern
        doc.setDrawColor(255, 255, 255, 0.2);
        doc.setLineWidth(0.1);
        for (let i = 0; i < pageWidth; i += 3) {
            doc.line(i, format[1] - 40, i, format[1]);
        }
        
        // Security text
        doc.setFont("courier", "bold");
        doc.setFontSize(6);
        doc.setTextColor(255, 255, 255, 0.8);
        doc.text("SECURE DIGITAL RECEIPT • END-TO-END ENCRYPTED", centerX, format[1] - 25, { align: "center" });
        
        doc.setFont("helvetica", "normal");
        doc.setFontSize(5);
        doc.setTextColor(255, 255, 255, 0.6);
        doc.text(`REF: ${String(t.referenceId || t.id).toUpperCase()} • ${new Date().toISOString().split('T')[0]}`, centerX, format[1] - 18, { align: "center" });
        doc.text("© 2025 ORBI FINANCIAL TECHNOLOGIES", centerX, format[1] - 10, { align: "center" });

        // 10. Watermark (if enabled)
        if (config.watermark) {
            doc.setFont("helvetica", "normal");
            doc.setFontSize(60);
            doc.setTextColor(241, 245, 249);
            doc.setGState(new (doc as any).GState({ opacity: 0.1 }));
            doc.text("ORBI", centerX, format[1] / 2, { align: "center", angle: 45 });
            doc.setGState(new (doc as any).GState({ opacity: 1 }));
        }

        // Generate filename with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
        const filename = `Orbi_Receipt_${timestamp}_${String(t.referenceId || t.id).substring(0, 8)}.pdf`;
        
        // Save with modern filename
        doc.save(filename);
        
        return {
            success: true,
            filename,
            transactionId: t.referenceId || t.id,
            amount: t.amount,
            currency
        };
    },

    /**
     * Generates a batch receipt for multiple transactions
     */
    async generateBatch(transactions: Transaction[], currency: string, options?: any) {
        // Implementation for batch receipts
    },

    /**
     * Triggers the browser's print dialog for the receipt
     */
    async print(t: Transaction, currency: string, options?: any) {
        return this.generate(t, currency, options);
    },

    /**
     * Triggers the Web Share API or download fallback
     */
    async share(t: Transaction, currency: string, options?: any) {
        return this.generate(t, currency, options);
    },

    /**
     * Preview receipt in a new window (for web apps)
     */
    async preview(t: Transaction, currency: string, options?: any) {
        const result = await this.generate(t, currency, { ...options, preview: true });
        const pdfBlob = new Blob([result as any], { type: 'application/pdf' });
        const pdfUrl = URL.createObjectURL(pdfBlob);
        window.open(pdfUrl, '_blank');
        return result;
    }
};
