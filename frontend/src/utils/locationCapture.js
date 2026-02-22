/**
 * Browser Location Capture for Zero-Trust Login
 * Supports Netlify deployment with browser geolocation API
 */

export async function captureBrowserLocation() {
  if (!navigator || !navigator.geolocation) {
    return {
      permission_status: "not_supported",
      latitude: null,
      longitude: null,
      accuracy_m: null
    };
  }

  try {
    // Check permission state if API available (modern browsers)
    if (navigator.permissions) {
      try {
        const permissionStatus = await navigator.permissions.query({ name: "geolocation" });
        if (permissionStatus.state === "denied") {
          return {
            permission_status: "denied",
            latitude: null,
            longitude: null,
            accuracy_m: null
          };
        }
      } catch (permError) {
        // permissions API not fully supported in all browsers, continue to geolocation prompt
      }
    }

    // Request geolocation (will prompt user if permission not yet granted)
    const position = await new Promise((resolve, reject) => {
      navigator.geolocation.getCurrentPosition(resolve, reject, {
        timeout: 8000,
        maximumAge: 0,
        enableHighAccuracy: false // faster, suitable for login
      });
    });

    return {
      permission_status: "granted",
      latitude: position.coords.latitude,
      longitude: position.coords.longitude,
      accuracy_m: position.coords.accuracy
    };
  } catch (error) {
    // User denied or timeout occurred
    if (error.code === 1) {
      return {
        permission_status: "denied",
        latitude: null,
        longitude: null,
        accuracy_m: null
      };
    } else if (error.code === 2) {
      return {
        permission_status: "unavailable",
        latitude: null,
        longitude: null,
        accuracy_m: null
      };
    } else if (error.code === 3) {
      return {
        permission_status: "timeout",
        latitude: null,
        longitude: null,
        accuracy_m: null
      };
    }

    return {
      permission_status: "error",
      latitude: null,
      longitude: null,
      accuracy_m: null
    };
  }
}
