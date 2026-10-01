import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.paintscope.app',
  appName: 'PaintScope',
  webDir: 'www',

  // Serve local assets over https on Android (matches iOS capacitor://).
  server: {
    androidScheme: 'https',
  },

  plugins: {
    PushNotifications: {
      // How foreground notifications present on iOS.
      presentationOptions: ['badge', 'sound', 'alert'],
    },
  },
};

export default config;
