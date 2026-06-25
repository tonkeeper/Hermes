
let isLogEnabled = true;

export function disableLogging() {
    isLogEnabled = false;
}

export function enableLogging() {
    isLogEnabled = true;
}

export function verbose(message?: any, ...optionalParams: any[]) {
    if (!isLogEnabled) {
        return
    }

    console.log(message, optionalParams.length > 0 ? optionalParams : undefined)
}