// 8G's maps, bundled into the page as text and parsed once.
import firewall from '../../../rules/8g-firewall.conf?raw'
import { parseFirewall } from './rules.ts'

export const GROUPS = parseFirewall(firewall)
