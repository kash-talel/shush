import { mount } from "svelte";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "./app.css";
import App from "./App.svelte";
import SpotlightOverlay from "./lib/components/SpotlightOverlay.svelte";

const target = document.getElementById("app");
if (!target) throw new Error("#app mount point missing");

// One frontend bundle, two windows: the Spotlight window (Ctrl+Alt+Space)
// renders only the quick-search overlay.
const Root = getCurrentWindow().label === "spotlight" ? SpotlightOverlay : App;

export default mount(Root, { target });
