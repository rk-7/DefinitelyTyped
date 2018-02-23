/**
 * Copyright 2017 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { cssClasses, strings, numbers } from './constants';

import { getCorrectEventName, getCorrectPropertyName } from 'material__animation';
import MDCFoundation from 'material__base/foundation';
import { MDCSliderAdapter } from './adapter';

export default class MDCSliderFoundation extends MDCFoundation<MDCSliderAdapter> {
    static readonly cssClasses: cssClasses;

    static readonly strings: strings;

    static readonly numbers: numbers;

    static readonly defaultAdapter: MDCSliderAdapter;

    setupTrackMarker(): void;

    layout(): void;

    getValue(): number;

    setValue(value: number): void;

    getMax(): number;

    setMax(max: number): void;

    getMin(): number;

    setMin(min: number): void;

    getStep(): number;

    setStep(step: number): void;

    isDisabled(): boolean;

    setDisabled(disabled: boolean): void;
}
