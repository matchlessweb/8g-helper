// The shipped 7G maps, bundled into the page as text and parsed once.
import mappings from '../../rules/gridpane-7g-mappings.conf?raw'
import { parseMappings } from './rules.ts'

export const GROUPS = parseMappings(mappings)
