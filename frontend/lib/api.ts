import axios from "axios";
import { ENV } from "./config";

export const api = axios.create({
  baseURL: ENV.API_BASE_URL,
  withCredentials: true,
  timeout: 15000,
});
